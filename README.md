**I am not responsible for any damage you do using this!**

<img src="https://i.ibb.co/nM06FQM/pitraix.png" width=400 height=400></img>
# Pitraix
Modern Cross-Platform HTTP-Based P2P Botnet over TOR that cannot be traced.

Design is based off "zero-trust" even malicious peers cannot do any damage while protecting operator identity, for reasoning behind this design check `spec.txt`

# Built-in Crypter and self-spreading
Pitraix has ability to self modify own code which results in a completely different executable in terms of hash on every new infection

All is done automagically and does not need operator intervention.


# Cross-platform with some sneaky 1-days
Pitraix works on Windows 7 all way to Windows 11 as well as linux

it has ability to automagically privilege escalate in both platforms

Linux it does so by keylogging password when user runs "sudo" or "doas"

Windows it uses a modified version of UACME (work in progress)


# Dynamic Behaviour
Pitraix automatically chooses different persistence locations on every host
Names of config files, pitraix it's self and more are all dynmically generated to confuse anti-viruses


# Anonymous and secure
- Hosts don't know each other, not even their their tor onion address

- Agents are hosts but have tor onion address of other hosts, agents relay instructions from operative to hosts. for reasoning behind this design check `spec.txt`

- Operatives are camaoflagued as agents to protect against advanced network timing and packets attacks over tor

# Features
- State-of-art encryption using AES-256 and public key crypto

- Peer-to-Peer over TOR

- Advanced Anti-VM detection

- Does not read or write any registry keys, thus lower detection

- Ability to keylog cross-platform even when run as user and not root

- Dynamic behaviour

- Built-in crypter

- Built-in ransomware that never stores keys on HOST (I am not responsible how you use this)

- Auto disable backup like Volume shadow copy, onedrive and windows backup

- Readiable code easy to modify, not alot of scattered files

- Events are anything interesting that happens on a host computer, currently it's tied only to keylogger

- Logs are mainly used for debugging behaviour and errors

Picture of working OPER
<img src="https://i.ibb.co/RCBW7NG/image.png"></img>


# Help
- Type "help" in OPER for list of commands

# Support
- This project is developed entirely by me in my free time, if you'd like to support me to keep updating, best way is via donating.

- Monero: `8AvS51UKvQ38howM6WPxLQ5yFyDgWd1ggUTwVBGRH7GYHiG9g4BemSe4u9pQdWQP6MPRXNGWQoJVqQPGWU3Cot8c5YgMFkY`

- Bitcoin (segwit): `bc1qy7amu3yarnctutyc2gm0zuqwrqcpjh676v0sld`

- Bitcoin (legacy): `1KcfixRTP4P2rFT1r9yHdQ9cCLNJqWCnPd`


# Trust
- For my GPG key please check `gpg.txt`

- Anyone who claims to be me and don't haven't signed a message with that key is NOT me

# Future
- This is a oldi-sh version of Pitraix, more advanced options will be added soon as I work on ironing out bugs
- Next release will be more bug-fixes, new instructions and modules support 
 
# Techincal
- Please read `spec.txt` for more techincal information

# Set up
- Download latest Go version for your platform
- Download files from releases and make sure they are all in same folder
- Compile lyst for platform you want
- Compile OPER (do NOT `go run OPER.go`! instead compile it THEN run the executable
- After running OPER for first time, it should automagically generate and embed RSA keys and TOR addresses into lyst executable

# Terms
- Operative/OPER means the botmaster

- Agent/AGS means a host that can relay instructions

- Host/HST means a host that does not relay instructions

- Instructions mean commands

- Host means a bot

- Hostring/cell means botnet


Have fun
