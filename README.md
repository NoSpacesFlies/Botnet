![Img](image.webp?raw=true "Screenshot")
Note: The cross compilers in script are not reliable and for ubuntu only
Note: Someone should do a pull request to add better compiler
# P.S: Update started at 11 may 2025
- Fixed segmentation errors, zombie connections and issues done for now (30% done)
# What is new? (2025-4-23 | 23 april 2025)
- Fixed segmentation error in command
- Fixed command crashing on no arguments
- Fixed terminal cursor for putty users when there are 2 sessions
- Fixed memory allocation in bot, optimising it (todo add slowmode opt)
- Fixed udpraw and syn raw methods
- Optimised command processor using Github Copilot AI (Structure)
- Added Raknet method (Raknet Unconnected ping flood)
- Added option psize for vse & raknet & udp & syn
- Added srcport option for udp,syn (useful on some servers)
- Added IP & File logging (settings.txt)
- Added auto bot compiler for ubuntu (not recommended, use another compilers)
- Bot Daemon spoofs itself now to avoid detection
- Fixed Duplicate botcount and added bot validator
- Finally added !opthelp & !exit for safe exit
- Took +30 hours for testing, optimising & best ai structure & code fixes
# Next update estimated times
- 5 May 2025
- 20 May 2025

# XS Botnet
- made by: daylight911 (discord), FuckIsra3l(telegram)
- Made in github codespaces(+Make & C ext)with copilot, there may be some bugs
# Features:
- Clear scren
- Stopall
- exit
- Global cooldown
- Anti duplicate users
- Works with putty
- Username, Password, Maxtime and maxbots customize!
- Command logs
- Arch list
- Almost undetectable by mirai killers (tested)
# Methods:
- Syn (Well Optimised & tested)
- Vse (Valve source engine query flood)
- UDP (Normal udp, No extra headers, just default)
- Socket (Connect flood no data, Not tested)
- http (HTTP 1.1 Get Attack)
- raknet (Bypasses some servers)
# Install tutorial?
- Check tutorial.txt

# Connection
- Putty raw using your vps ip and cnc port

### IMPORTANT NOTES:
- Todo: Fix stupid shit Disconnect terminal (They are immune to be disconnected again because of shit code)
- Fix always logged in even if socket closed
