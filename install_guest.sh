# Tested on Ubuntu-20.04
# Run as root
# Author: Neelima Krishnan
# Date: 10-06-2022

bash proxy.sh
apt -y install libguestfs-tools

set -e

if [ -z $1 ];then
	echo "No OS-version passed, installing default -> ubuntu-18.04"
	OS_VER=ubuntu-20.04
else
	OS_VER=$1
fi

export LIBGUESTFS_BACKEND=direct
virt-builder -v $OS_VER --root-password password:labuser --format qcow2 --hostname vm-$OS_VER -o /var/lib/libvirt/images/$OS_VER.qcow2 --copy-in ./iproxy2.sh:/root --run-command /root/iproxy2.sh --edit '/etc/default/grub: s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0"/' --run-command '/usr/sbin/update-grub2 || true'

virt-install --name $OS_VER --ram 2048 \
        --disk path=/var/lib/libvirt/images/$OS_VER.qcow2 \
        --nographics \
        --import

virsh start $OS_VER --console
