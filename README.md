# setup_vm
Install packages 
```
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager
```
TO install VM
```
sudo ./install_vm.sh
```
To start VM:
```
sudo virsh start ubuntu-20.04 --console 
```
To add a device:
```
sudo virsh attach-device ubuntu-20.04 *.xml --live
```
