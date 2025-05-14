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

# New changelog: 13 may 2025 (7:35 / GMT+3)
- Fixed Some buffer overflows
- Optimised all methods
- Placed header file in /Headers file for better structure
- Added method ICMP
- Fixed crash from little endian bots
- Fixed invalid data crashing cnc
- Fixed memory leaks
- Changed theme to pink
- Added Bot join logs
- Fixed zombie connection on linux terminals
- Fixed PUTTY Sometimes Login failure due to extra characters or buffer
- optimised udp and syn methods for pps
- Changed !help command
- Added botcount= option to limit bots

NEXT UPDATE TODO LIST:
- Fix zombie connections on putty & linux
- Add admin permission
- Add !adduser and !deleteuser
- Make !stopall for admin only unless allowed in settings
- Add gre method
- Add more fake names to bot (e.g: init, bash) instead of "update"
- Add debug & production compiler (e.g, you cant get rid of bot while testing because you will kill init proc)