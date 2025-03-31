# shadowrust

hello! this is **shadowrust**, a ransomware proof-of-concept (PoC) i messed around with in rust. it’s not production malware—don’t be a dick with it—it’s just for learning how rust works. encrypts user files (documents, pictures, downloads), skips windows system dirs, tries to escalate privileges, sets boot persistence, and deletes itself. got some anti-vm and anti-debug tricks too. built for windows, cross-compiled from linux.

## what it does
- **anti-analysis**: checks for VMs (bios, disk size) and debuggers (timing, process checks). quits if its a sandbox.
- **privilege escalation**: tries to grab SYSTEM privs with sedebugprivilege and impersonation. lazy PID 4 placeholder—fix that if you care.
- **boot persistence**: registers a service (`ShadowSvc`) to run on startup. needs admin, not a real bootkit tho maybe ill post one.
- **encryption**: uses xchacha20-poly1305 to lock files recursively in user dirs. adds `.shadowXXXXXX` extensions, deletes originals.
- **ransom note**: drops a `README.txt` on the desktop with fake payment shit (1000 euros in XMR lol).
- **self-delete**: runs a hidden cmd to wipe itself after 2 seconds.
  
## how to build it
- **setup**: you need rust and a windows cross-compiler. i used `x86_64-pc-windows-gnu` on arch linux.
- **deps**: check `Cargo.toml`—needs `windows`, `chacha20poly1305`, `sha2`, `rand`, `whoami`.
- **compile**: cargo build --release --target x86_64-pc-windows-gnu
- **output**: grab `target/x86_64-pc-windows-gnu/release/shadowrust.exe`.

## how to run it
- copy the exe to a windows VM (don’t fuck your real box lmfao).
- run as admin for full effect—privilege escalation and service stuff need it.
- it’ll ping google.com (XORed as `HOST`), encrypt shit, drop the note, and poof itself. check `Documents`, `Pictures`, `Downloads` for `.shadowXXXXXX` files.

## sources i looked at
 i didn’t invent this from scratch—here’s where i pulled ideas and fixes from:
- **rust docs**: [doc.rust-lang.org](https://doc.rust-lang.org) - basics for rust syntax and stdlib shit like `fs` and `env`.
- **windows crate**: [docs.rs/windows](https://docs.rs/windows/0.57.0/windows/) - api docs for all the `Win32_*` calls (registry, services, tokens).
- **microsoft docs**: [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/api/) - win32 api details for stuff like `CreateServiceW`, `ShellExecuteW`, and token privilege crap.
- **chacha20poly1305 crate**: [docs.rs/chacha20poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/) - how to use xchacha20-poly1305 for encryption.
- **sha2 crate**: [docs.rs/sha2](https://docs.rs/sha2/0.10.8/sha2/) - hashing for key/nonce generation.
- **malware dev forums**: random threads on anti-vm/debug tricks (no links, just google “anti vm techniques” or “anti debug windows”).
- **stack overflow**: bits for rust/windows interop fixes, like handling `PWSTR` and service config.

## notes
- **lazy af**: XOR obfuscation sucks—i said it in the code, use AES if you’re serious. privilege escalation’s basic too, real shit needs process enumeration or UAC bypass (maybe ill post a windows 0day here eventually).
- **educational only**: this is for learning ransomware mechanics, not screwing people. test in a VM, not your mom’s laptop.
- **pre-os dream**: wanted bootkit vibes but settled for a service. real pre-OS needs a custom bootloader—out of scope here.

## todo maybe
- swap XOR for AES or something less shitty.
- better privilege escalation (enumerate SYSTEM PIDs or UAC exploit).
- fake GUI to trick users into running it.
- network C2 for key exfil.

hit me up if you fork this and make it cooler. just don’t be a dick with it.
thanks to music, random chinese documents and a multitude of other shit for helping me make this

colab with me! noctol@tutanota.com
