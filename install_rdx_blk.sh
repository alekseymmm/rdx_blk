#/usr/bin/bash
modprobe nvme
insmod rdx_blk.ko main_bdev_path="/dev/nvme0n1" aux_bdev_path="/dev/nvme1n1" msb_range_size_sectors=40960 max_num_evict_cmd=128
echo "module rdx_blk =pflt" > /sys/kernel/debug/dynamic_debug/control
