**I am not responsible for any damage you do using this!**

<img src="https://i.ibb.co/nM06FQM/pitraix.png" width=400 height=400></img>
# Pitraix
Modern Cross-Platform HTTP-Based P2P Botnet over TOR that cannot be traced
Design is based off intelligence agencies structures for reasoning behind this design check `spec.txt`

# Built-in Crypter and self-spreading
Pitraix has ability to self modify it's own code which results in a completely different executable in terms of hash on every Host infection.

it is done automatically and does not need operator intervention.

# Cross-platform with some sneaky 1-days
Pitraix works on windows 7 all way to windows 11 as well as linux

it has ability to automatically privilege escalate on both, linux and windows.

on linux it does so by keylogging password when user runs "sudo" or "doas"

on windows it uses a modified version of UACME (work in progress)

- This release will only include windows version, next release will be linux as I iron out bugs from linux port

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
- My one and only GPG key is followig:
`-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=eTh5
-----END PGP PUBLIC KEY BLOCK-----`

- Anyone who claims to be me and don't have that key on their profile is NOT me

# Future
- This is a oldi-sh version of Pitraix, more advanced options will be added soon as I work on ironing out bugs
- For example python and powershell Modules support will be added soon alongside alot of bug fixes 

# Techincal
- Please read `spec.txt` for more techincal information

# Terms
Operative/OPER means the botmaster

Agent/AGS means a host that can relay instructions

Host/HST means a host that does not relay instructions

Instructions mean commands

Host means a bot

Hostring/cell means botnet


# Set up
- Put your RSA key PEM encoded in OPER.go

- Set up a hidden TOR service on port 1337 and place your tor address in lyst.go

- You don't to have TOR service on all time, as this is peer to peer. also your tor address embdedded inside will change to other hosts addresses automatically by crypter

have fun
