#/usr/bin/bash
modprobe nvme
#insmod rdx_blk.ko main_bdev_path="/dev/nvme0n1" aux_bdev_path="/dev/nvme1n1" msb_range_size_sectors=16384 max_num_evict_cmd=128
insmod rdx_blk.ko main_bdev_path="/dev/md/md14_store" aux_bdev_path="/dev/md/md14_wal" msb_range_size_sectors=8192 max_num_evict_cmd=128
echo "module rdx_blk =pflt" > /sys/kernel/debug/dynamic_debug/control
