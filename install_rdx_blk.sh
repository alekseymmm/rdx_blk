#/usr/bin/bash
modprobe nvme
insmod rdx_blk.ko main_bdev_path="/dev/nvme0n1" aux_bdev_path="/dev/nvme1n1"
echo "module rdx_blk =pflt" > /sys/kernel/debug/dynamic_debug/control
