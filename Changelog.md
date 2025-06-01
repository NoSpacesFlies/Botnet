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

# New changelog: 13 may 2025 (7:35 PM / GMT+3)
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

# New changelog: 18 may 2025 (3:50 AM / GMT+3)
- Added simple killer for known qbots
- Added !adduser
- Added blacklisted targets txt
- Moved txt items logins,logs etc into /database
- Improvement in daemon
- Added !user command
- Added !removeuser command
- Added anti targetting for local ips/subnets
- Added greip method With types IP,TCP,UDP
- Added !kickuser command
- Added more settings (globalstopall|rootuser|globalusercommand)
- Added admin option in logins.txt
- Added Users online page in terminal title
- Fixed duplicate bots in terminal title (DELAY)
- Changed max bot reconnect attempts to 13 instead of 7 earlier
- Attempted to fix stopall, not sure

# Big changelogs: 24 May To 1 June 2025
- Added arc cross compiler
- Added udpplain
- Improved UDP Method
- Fixed buffer overflows
- Fixed memory leaks
- Improved daemon to be more safe
- Bots reload every 5 minutes.
- Fixed cnc killing non-duplicate bots
- Fixed GRE Crash (auto size select)
- Improved SYN Method
- Added online users title
NEXT UPDATE TODO LIST:
- Fix zombie connections on putty & linux (edit: done 2025 18 may)
- Add admin permission (edit: dont 2025 18 may)
- Add !adduser and !deleteuser (edit: done 2025 18 may)
- Make !stopall for admin only unless allowed in settings (edit: done 2025 18 may)
- Add gre method (edit: added 2025 18 may)
- Add more fake names to bot (e.g: init, bash) instead of "update" (edit: added 2025 18 may)
- Add debug & production compiler (e.g, you cant get rid of bot while testing because you will kill init proc) (Not done)
