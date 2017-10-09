/**
 * @file rdx_test.c
 * @brief rdx test
 * @author dima
 */

/*
 * Usage:
 * For creating real device:
 * echo 'add /dev/sdc' > /sys/bus/rdx/drivers/rdx_driver/control
 * echo 'create lunec' > /sys/bus/rdx/drivers/rdx_driver/control
 * echo 'destroy lunec' > /sys/bus/rdx/drivers/rdx_driver/control
 * 
 * For creating emu device, size = 100mb:
 * echo 'emu lunec 100' > /sys/bus/rdx/drivers/rdx_driver/control
 * echo 'destroy lunec' > /sys/bus/rdx/drivers/rdx_driver/control
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/list.h>
#include <trace/events/block.h>
#include <linux/delay.h>

#define KERNEL_SECTOR_SIZE	512
#define RDX_MINORS		16
#define RDX_BLKDEV_NAME		"rdx"
#define RDX_BLOCK_SIZE_SECTORS	(4096 / KERNEL_SECTOR_SIZE)

#define RDX_ADD_CMD		"add"
#define RDX_CLEAR_CMD		"clear"
#define RDX_CREATE_CMD		"create"
#define RDX_DESTROY_CMD		"destroy"
#define RDX_EMU_CMD		"emu"
#define RDX_DEV_NAME		"rdx_%s"

unsigned int skip = 0;

struct rdx_device {
	char			*name;
	struct block_device	**bdev;
	int			bdev_cnt;
	sector_t		sectors;	/* Device size in sectors */
	uint64_t		bytes;		/* Device size in bytes */
	struct request_queue	*queue;
	struct gendisk		*gd;
	struct list_head	list;
	uint64_t		disk_size;
	char			*data;		/* For emu */
};

struct rdx_disk {
	char			*path;
	struct list_head	list;
};

struct rdx_request {
	struct rdx_device	*dev;
	struct bio		*usr_bio;
	atomic_t		ref_cnt;
	unsigned int		rw;
	sector_t		first_sector;
	int			err;
	uint64_t		bytes;
};

enum rdx_log_level {
	RDX_LOG_INFO		= BIT(0),
	RDX_LOG_ERROR		= BIT(1),
};

#define rdx_print(log_mask, fmt, ...)					\
	do {								\
		if (log_mask & RDX_LOG_INFO) {				\
			printk("rdx_info: %s:%d: " fmt, __FUNCTION__,	\
			       __LINE__, ##__VA_ARGS__);		\
		} else if (log_mask & RDX_LOG_ERROR) {			\
			printk("rdx_error: %s:%d: " fmt, __FUNCTION__,	\
			       __LINE__, ##__VA_ARGS__);		\
		}							\
	} while (0)

#define rdx_info(fmt, ...)	rdx_print(RDX_LOG_INFO, fmt, ##__VA_ARGS__)
#define rdx_error(fmt, ...)	rdx_print(RDX_LOG_ERROR, fmt, ##__VA_ARGS__)

LIST_HEAD(rdx_dev_list);
LIST_HEAD(rdx_emudev_list);
LIST_HEAD(rdx_disk_list);
static int rdx_disk_cnt = 0;
static int rdx_major = 0;
static int rdx_dev_cnt = 0;

/* SYSFS */
static int rdx_bus_match(struct device *dev, struct device_driver *driver)
{
	return 1;
}

static void rdx_device_release(struct device *dev)
{
}

struct bus_type rdx_bus = {
	.name		= "rdx",
	.match		= rdx_bus_match,
};

struct device_driver rdx_driver = {
	.name		= "rdx_driver",
	.bus		= &rdx_bus,
};

static struct device rdx_parent = {
	.init_name	= "rdx_parent",
	.bus		= &rdx_bus,
	.release	= rdx_device_release,
};

static struct block_device_operations rdx_ops = {
	.owner =	THIS_MODULE,
};

static struct bio *rdx_bio_split_clone(struct bio *bio, int sectors)
{
	struct bio *split;

	BUG_ON(sectors >= bio_sectors(bio));
	
	split = bio_clone(bio, GFP_NOIO);
	if (!split)
		return NULL;

	split->bi_size = sectors << 9;
	bio_advance(bio, split->bi_size);

	return split;
}

static void __req_put(struct rdx_request *req)
{
	if (atomic_dec_and_test(&req->ref_cnt)) {
		struct bio *bio = req->usr_bio;

                trace_block_bio_complete(bdev_get_queue(bio->bi_bdev),
                                         bio, req->err);
		bio_endio(bio, req->err);
		kfree(req);
	}
}

static void __end_transfer(struct bio *bio, int err)
{
	struct rdx_request *req = bio->bi_private;

	if (!req->err)
		req->err = err;

	__req_put(req);

	/* Complete our bio */
	bio_put(bio);
}

static void __start_transfer(struct rdx_request *req)
{
	struct bio *clone;
	int sectors;

	clone = bio_clone(req->usr_bio, GFP_NOIO);
	if (!clone) {
		rdx_error("Cannot clone bio\n");
		req->err = -ENOMEM;
		__req_put(req);
		return;
	}

	clone->bi_bdev = req->dev->bdev[0];
	clone->bi_private = req;
	clone->bi_end_io = __end_transfer;

	sectors = bio_sectors(clone);
	while (sectors) {
		if (sectors > RDX_BLOCK_SIZE_SECTORS) {
			struct bio *split;

			split = rdx_bio_split_clone(clone,
						    RDX_BLOCK_SIZE_SECTORS);
			if (!split) {
				rdx_error("Cannot split clone\n");
				bio_put(clone);
				req->err = -ENOMEM;
				__req_put(req);
				return;
			}

			split->bi_private = req;
			split->bi_end_io = __end_transfer;

			sectors -= bio_sectors(split);
			atomic_inc(&req->ref_cnt);
			submit_bio(req->rw, split);
		} else {
			sectors -= bio_sectors(clone);
			atomic_inc(&req->ref_cnt);
			submit_bio(req->rw, clone);
		}
	}

	__req_put(req);
}

static void __make_request(struct request_queue *q, struct bio *bio)
{
	struct rdx_device *dev = q->queuedata;
	struct rdx_request *req;

        if (skip) {
                trace_block_bio_complete(q, bio, 0);
                bio_endio(bio, 0);
                return;
        }

	if (!bio_sectors(bio)) {
		bio_endio(bio, 0);
		return;
	}

	req = kzalloc(sizeof(struct rdx_request), GFP_KERNEL);
	if (!req) {
		rdx_error("Cannot allocate request\n");
		bio_io_error(bio);
		return;
	}

	req->bytes = bio_sectors(bio) * KERNEL_SECTOR_SIZE;
	req->dev = dev;
	req->usr_bio = bio;
	req->first_sector = bio_end_sector(bio) - bio_sectors(bio);
	atomic_set(&req->ref_cnt, 1);

	__start_transfer(req);
}

static void __emu_xfer(struct rdx_device *dev, sector_t sector,
		sector_t nsect, char *buffer, int write)
{
	uint64_t offset = sector * KERNEL_SECTOR_SIZE;
	uint64_t nbytes = nsect * KERNEL_SECTOR_SIZE;

	if ((offset + nbytes) > dev->bytes) {
		rdx_error("Beyond-end io (%llu %llu)\n", offset, nbytes);
		return;
	}

	if (write)
		memcpy(dev->data + offset, buffer, nbytes);
	else
		memcpy(buffer, dev->data + offset, nbytes);
}

/* TODO: doesn't work */
static void __emu_request(struct request_queue *q, struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	sector_t sector = bio->bi_sector;
	struct rdx_device *dev = q->queuedata;
	
	if (skip) {
                trace_block_bio_complete(q, bio, 0);
                bio_endio(bio, 0);
                return;
        }

	if (!bio_sectors(bio)) {
		bio_endio(bio, 0);
		return;
	}

	/* Do each segment independently. */
	bio_for_each_segment(bvec, bio, i) {
		char *buffer = __bio_kmap_atomic(bio, i, KM_USER0);
		__emu_xfer(dev, sector,
			   bio_cur_bytes(bio) / KERNEL_SECTOR_SIZE,
			   buffer, bio_data_dir(bio) == WRITE);
		sector += bio_cur_bytes(bio) / KERNEL_SECTOR_SIZE;
		__bio_kunmap_atomic(bio, KM_USER0);
	}

	bio_endio(bio, 0);

}

static void __destroy_device(struct rdx_device *dev)
{
	struct request_queue *queue = dev->queue;
	struct gendisk *gd = dev->gd;
	int i;

	rdx_info("Destroying device %s\n", dev->name);

	if (gd) {
		rdx_dev_cnt--;
		del_gendisk(gd);
		put_disk(gd);
	}

	if (queue)
		blk_cleanup_queue(queue);

	for (i = 0; i < dev->bdev_cnt; i++)
		blkdev_put(dev->bdev[i], FMODE_READ|FMODE_WRITE);

        if (dev->bdev)
            kfree(dev->bdev);
	if (dev->name)
            kfree(dev->name);
        if (dev->data)
            vfree(dev->data);
	kfree(dev);

	rdx_info("Device destroyed\n");
}

static void __create_device(char *name, unsigned int emu_size)
{
	struct rdx_device *dev;
	struct rdx_disk *disk;
	struct request_queue *queue;
	struct gendisk *gd;

	rdx_info("Creating device %s\n", name);

	dev = kzalloc(sizeof(struct rdx_device), GFP_KERNEL);
	if (!dev) {
		rdx_error("Cannot allocate device %s\n", name);
		return;
	}

	dev->name = kstrdup(name, GFP_KERNEL);
	if (!dev->name) {
		rdx_error("Cannot allocate name %s\n", name);
		goto out;
	}

	if (!emu_size) {
		dev->bdev = kcalloc(rdx_disk_cnt, sizeof(struct block_device),
				GFP_KERNEL);
		if (!dev->bdev) {
			rdx_error("Cannot allocate bdev array for dev %s\n", name);
			goto out;
		}

		list_for_each_entry(disk, &rdx_disk_list, list) {
			struct block_device *bdev;
			bdev = blkdev_get_by_path(disk->path,
						  FMODE_READ|FMODE_WRITE, dev);
			if (IS_ERR(bdev)) {
				rdx_error("Cannot open bdev %s\n", disk->path);
				goto out;
			}

			dev->bdev[dev->bdev_cnt] = bdev;
			dev->sectors += get_capacity(bdev->bd_disk);
			dev->bdev_cnt++;
		}

		dev->bytes = dev->sectors * KERNEL_SECTOR_SIZE;
		dev->disk_size = dev->bytes / dev->bdev_cnt;
		/* TODO: we should use min disk size */
	} else {
		BUG_ON(!emu_size);
		dev->bytes = (uint64_t)emu_size * 1024 * 1024;
		dev->sectors = dev->bytes / KERNEL_SECTOR_SIZE;
		dev->data = vmalloc(dev->bytes);  // no zeroes
		if (!dev->data)
			rdx_error("ERROR\n");
	}

	queue = blk_alloc_queue(GFP_KERNEL);
	if (!queue) {
		rdx_error("Cannot allocate queue for %s\n", name);
		goto out;
	}

	blk_queue_make_request(queue,
			       emu_size ? __emu_request : __make_request);
	dev->queue = queue;
	queue->queuedata = dev;

	gd = alloc_disk(RDX_MINORS);
	if (!gd) {
		rdx_error( "alloc_disk failure\n");
		goto out;
	}

	dev->gd = gd;
	gd->private_data = dev;
	gd->queue = queue;
	gd->major = rdx_major;
	/* TODO: first should be index or index*MINORS, but not MINORS */
	gd->first_minor = rdx_dev_cnt;
        rdx_dev_cnt++;
	gd->minors = RDX_MINORS;
	gd->flags |= GENHD_FL_EXT_DEVT;
	gd->fops = &rdx_ops;
	snprintf(gd->disk_name, DISK_NAME_LEN, RDX_DEV_NAME, dev->name);
	set_capacity(gd, dev->sectors);
	add_disk(gd);

	list_add_tail(&dev->list, &rdx_dev_list);

	rdx_info("Device %s created, size %llu Mb\n", gd->disk_name,
		 dev->bytes / 1024 / 1024);
	return;

out:
	__destroy_device(dev);
}

static void __clear_disk_list(void)
{
	struct rdx_disk *disk, *next_disk;

	rdx_info("Clearing disk list\n");
	list_for_each_entry_safe(disk, next_disk, &rdx_disk_list, list) {
		list_del(&disk->list);
		kfree(disk->path);
		kfree(disk);
	}
	rdx_disk_cnt = 0;
	rdx_info("Disk list cleared\n");
}

static void __add_disk(char *path)
{
	struct rdx_disk *disk;

	rdx_info("Adding disk %s to the list\n", path);
	disk = kzalloc(sizeof(struct rdx_disk), GFP_KERNEL);
	if (!disk) {
		rdx_error("Cannot allocate device %s\n", path);
		return;
	}

	disk->path = kstrdup(path, GFP_KERNEL);
	if (!disk->path) {
		rdx_error("Cannot allocate path %s\n", path);
		kfree(disk);
		return;
	}

	list_add_tail(&disk->list, &rdx_disk_list);
	rdx_disk_cnt++;
	rdx_info("Disk %s added to the list\n", path);
}

static void __destroy_device_by_name(char *name)
{
	struct rdx_device *dev;

	list_for_each_entry(dev, &rdx_dev_list, list) {
		if (!strncmp(dev->name, name, strlen(name))) {
			list_del_init(&dev->list);
			__destroy_device(dev);
			break;
		}
	}
	list_for_each_entry(dev, &rdx_emudev_list, list) {
		if (!strncmp(dev->name, name, strlen(name))) {
			list_del_init(&dev->list);
			__destroy_device(dev);
			break;
		}
	}
}

static ssize_t __store_control(struct device_driver *driver, const char *buf,
			       size_t count)
{
	const char *ptr = buf;
	unsigned int scanned;
	unsigned int size = 0;
	char cmd[32];
	char path[32];
	char name[32];

	rdx_info("Command: %s\n", ptr);

	if (sscanf(ptr, "%32s", cmd) == 1) {
		scanned = strlen(cmd);
		ptr += scanned;
	} else {
		rdx_error("Cannot parse command\n");
		return count;
	}

	if (!strncmp(cmd, RDX_ADD_CMD, scanned)) {
		if (sscanf(ptr, "%32s", path) == 1)
			__add_disk(path);
		else
			rdx_error("Cannot parse path\n");
	} else if (!strncmp(cmd, RDX_CLEAR_CMD, scanned)) {
		__clear_disk_list();
	} else if (!strncmp(cmd, RDX_CREATE_CMD, scanned)) {
                if (sscanf(ptr, "%32s", name) == 1) {
			__create_device(name, size);
			__clear_disk_list();
		} else {
			rdx_error("Cannot parse name\n");
		}
	} else if (!strncmp(cmd, RDX_DESTROY_CMD, scanned)) {
		if (sscanf(ptr, "%32s", name) == 1)
			__destroy_device_by_name(name);
		else
			rdx_error("Cannot parse name\n");
	} else if (!strncmp(cmd, RDX_EMU_CMD, scanned)) {
		if (sscanf(ptr, "%32s %u", name, &size) == 2) {
			__create_device(name, size);
		} else {
			rdx_error("Cannot parse name and size\n");
		}
	} else {
		rdx_error("Unsupported command\n");
        }

	return count;
}

static DRIVER_ATTR(control, S_IWUSR, NULL, __store_control);

static int __init rdx_init(void)
{
	int ret = 0;

	ret = bus_register(&rdx_bus);
	if (ret < 0) {
		rdx_error("Cannot register bus\n");
		return -ENOMEM;
	}

	ret = driver_register(&rdx_driver);
	if (ret < 0) {
		rdx_error("Cannot register driver\n");
		goto out_free_bus;
	}

	ret = driver_create_file(&rdx_driver, &driver_attr_control);
	if (ret < 0) {
		rdx_error("Unable to create last_error attribute.\n");
		goto out_free_driver;
	}

	ret = device_register(&rdx_parent);
	if (ret < 0) {
		rdx_error("Cannot register device\n");
		goto out_free_control;
	}

	rdx_major = register_blkdev(rdx_major, RDX_BLKDEV_NAME);
	if (rdx_major <= 0) {
		rdx_error("unable to get major number\n");
		goto out_free_parent;
	}

	return ret;

out_free_parent:
	device_unregister(&rdx_parent);
out_free_control:
	driver_remove_file(&rdx_driver, &driver_attr_control);
out_free_driver:
	driver_unregister(&rdx_driver);
out_free_bus:
	bus_unregister(&rdx_bus);
	return -1;
}

static void rdx_exit(void)
{
	struct rdx_device *dev, *next_dev;

	__clear_disk_list();

	list_for_each_entry_safe(dev, next_dev, &rdx_dev_list, list) {
		list_del(&dev->list);
		__destroy_device(dev);
	}
	list_for_each_entry_safe(dev, next_dev, &rdx_emudev_list, list) {
		list_del(&dev->list);
		__destroy_device(dev);
	}

	unregister_blkdev(rdx_major, RDX_BLKDEV_NAME);
	device_unregister(&rdx_parent);
	driver_remove_file(&rdx_driver, &driver_attr_control);
	driver_unregister(&rdx_driver);
	bus_unregister(&rdx_bus);
}

module_init(rdx_init);
module_exit(rdx_exit);

MODULE_PARM_DESC( skip, "skip" );
module_param_named( skip, skip, uint, S_IRUGO | S_IWUSR );

MODULE_AUTHOR("rdx");
MODULE_DESCRIPTION("rdx test driver");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");
