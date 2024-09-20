#!/bin/bash
# Copyright GuestSneezeOSDev, All Rights Reserved

wget https://mirrors.edge.kernel.org/pub/linux/utils/util-linux/v2.39/util-linux-2.39.tar.xz
tar -xvf util-linux-2.39.tar.xz
cd util-linux-2.39
./configure --without-ncurses --disable-all-programs --enable-fdisk
make fdisk
cp disk-utils/fdisk ~/rootfs/usr/sbin/
ldd ~/rootfs/usr/sbin/fdisk
cd ..

wget https://downloads.sourceforge.net/project/e2fsprogs/e2fsprogs/1.46.5/e2fsprogs-1.46.5.tar.gz
tar -xzf e2fsprogs-1.46.5.tar.gz
cd e2fsprogs-1.46.5
./configure --disable-shared --enable-static
make mkfs.ext4
cp e2fsck/mkfs.ext4 ~/rootfs/usr/sbin/
ldd ~/rootfs/usr/sbin/mkfs.ext4
cd ..

wget https://ftp.gnu.org/gnu/tar/tar-1.34.tar.gz
tar -xzf tar-1.34.tar.gz
cd tar-1.34
./configure --disable-shared --enable-static
make
cp src/tar ~/rootfs/usr/sbin/
ldd ~/rootfs/usr/sbin/tar
strip ~/rootfs/usr/sbin/tar
cd ..

wget https://ftp.gnu.org/gnu/grub/grub-2.06.tar.gz
tar -xzf grub-2.06.tar.gz
cd grub-2.06
./configure --prefix=/home/$USER/rootfs/usr --with-platform=pc --target=x86_64
make
make install
cd ..

wget https://ftp.gnu.org/gnu/coreutils/coreutils-9.2.tar.xz
tar -xf coreutils-9.2.tar.xz
cd coreutils-9.2
./configure --prefix=/home/$USER/rootfs/usr
make
make install
ldd ~/rootfs/usr/bin/chroot
cd ..

cp -r ~/rootfs/initramfs.cpio.gz ~/rootfs/
cat << 'EOF' > ~/rootfs/install.sh
#!/bin/sh
DISK='/dev/sda'
BOOT_PARTITION="${DISK}1"
ROOT_PARTITION="${DISK}2"
MOUNT_POINT='/mnt'
ROOTFS_TARBALL='/initramfs.cpio.gz'
KERNEL_IMAGE='/boot/kernel.bin'
INITRD_IMAGE='/boot/initramfs.cpio.gz'

fdisk $DISK <<EOF_FDISK
o      
n      
p      
1      
      
+500M  
n      
p      
2      
        
      
a     
1      
w      
EOF_FDISK

/usr/sbin/mkfs.ext4 $BOOT_PARTITION
/usr/sbin/mkfs.ext4 $ROOT_PARTITION
mkdir -p $MOUNT_POINT
mount $ROOT_PARTITION $MOUNT_POINT
mkdir -p $MOUNT_POINT/boot
mount $BOOT_PARTITION $MOUNT_POINT/boot
/usr/sbin/tar -xzf $ROOTFS_TARBALL -C $MOUNT_POINT
/usr/bin/chroot $MOUNT_POINT /bin/sh <<EOF_CHROOT
/usr/sbin/grub-install --target=i386-pc --boot-directory=/boot $DISK
/usr/sbin/grub-mkconfig -o /boot/grub/grub.cfg
echo '
set default=0
set timeout=5

insmod ext2

set root=(hd0,msdos1)

menuentry "NexOS" {
    linux /kernel.bin root=/dev/sda1

    initrd /initramfs.cpio.gz
}
' >> /boot/grub/grub.cfg
echo "Configuring fstab..."
cat <<EOF_FSTAB > /etc/fstab
$ROOT_PARTITION  /               ext4    defaults        1 1
$BOOT_PARTITION  /boot           ext4    defaults        1 2
EOF_FSTAB
EOF_CHROOT

umount $MOUNT_POINT/boot
umount $MOUNT_POINT
reboot
EOF

chmod +x ~/rootfs/install.sh
