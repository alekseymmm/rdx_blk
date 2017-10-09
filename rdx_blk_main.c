#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>

#include "rdx_blk.h"
#include "rdx_blk_request.h"


char RDX_BLKDEV_NAME[32] = "rdx_blk";

static struct mutex lock;
static int rdx_major;
static int rdx_minor = 1;
static int blocksize = 4096;

struct rdx_blk *rdx_blk = NULL;
struct msb_data *rdx_msb_data = NULL;

struct kmem_cache *rdx_request_cachep = NULL;

static char *main_bdev_path = "/dev/md/storage_14";
module_param(main_bdev_path, charp, 0000);
MODULE_PARM_DESC(main_bdev_path, "Path to main storage block device");

static char *aux_bdev_path = "/dev/md/wal_14";
module_param(aux_bdev_path, charp, 0000);
MODULE_PARM_DESC(aux_bdev_path, "Path to buffer storage block device");

static int home_node = NUMA_NO_NODE;
module_param(home_node, int, S_IRUGO);
MODULE_PARM_DESC(home_node, "Home node for the device");

static unsigned long msb_range_size_sectors = 40960;
module_param(msb_range_size_sectors, ulong, S_IRUGO);
MODULE_PARM_DESC(msb_range_size_sectors, "Range size in 512b sectors");

static unsigned long max_num_evict_cmd = 8;
module_param(max_num_evict_cmd, ulong, S_IRUGO);
MODULE_PARM_DESC(msb_range_size_sectors, "Maximal number of eviction commands");

static int rdx_blk_open(struct block_device *bdev, fmode_t mode){
	return 0;
}

static void  rdx_blk_release(struct gendisk *disk, fmode_t mode){
}

static const struct block_device_operations rdx_blk_fops ={
		.owner = THIS_MODULE,
		.open = rdx_blk_open,
		.release = rdx_blk_release,
};

static void rdx_destroy_dev(void)
{
	pr_debug("Destroying device %s\n", RDX_BLKDEV_NAME);

	if(rdx_blk == NULL){
		pr_debug("rdx_blk s NULL. Destroyed\n");
		return;
	}
	if(rdx_blk->name){
		kfree(rdx_blk->name);
	}

	if(rdx_blk->split_bioset){
		bioset_free(rdx_blk->split_bioset);
	}

	if(rdx_blk->gd){
		del_gendisk(rdx_blk->gd);
		put_disk(rdx_blk->gd);
		pr_debug("For dev %s gendisk deleted\n", RDX_BLKDEV_NAME);
	}

	if(rdx_blk->queue){
		blk_cleanup_queue(rdx_blk->queue);
		pr_debug("For dev %s queue cleaned\n", RDX_BLKDEV_NAME);
	}

	if(rdx_blk->main_bdev){
		blkdev_put(rdx_blk->main_bdev, FMODE_READ | FMODE_WRITE);
		pr_debug("For dev %s put main_bdev\n", RDX_BLKDEV_NAME);
	}

	if(rdx_blk->aux_bdev){
		blkdev_put(rdx_blk->aux_bdev, FMODE_READ | FMODE_WRITE);
		pr_debug("For dev %s put aux_bdev\n", RDX_BLKDEV_NAME);
	}

	kfree(rdx_blk);
	rdx_blk = NULL;
	pr_debug("Device %s destroyed \n", RDX_BLKDEV_NAME);
}


static int rdx_blk_create_dev(void)
{
	struct gendisk *gd;
	int ret = 0;

	rdx_blk = kzalloc_node(sizeof(struct rdx_blk), GFP_KERNEL, home_node);
	if(!rdx_blk){
		ret = -ENOMEM;
		pr_debug("Not enough memory for allocating rdx_blk\n");
		goto out;
	}

	rdx_blk->name = kstrdup(RDX_BLKDEV_NAME, GFP_KERNEL);
	if(!rdx_blk->name){
		ret = -ENOMEM;
		pr_debug("Cannot allocate name %s \n", RDX_BLKDEV_NAME);
		goto out;
	}
	pr_debug("Device %s allocated\n", rdx_blk->name);

	rdx_blk->split_bioset = bioset_create_nobvec(RDX_BLK_MIN_POOL_PAGES, 0);
	if(!rdx_blk->split_bioset){
		ret = -ENOMEM;
		pr_debug("Cannot allocate bioset of size %d\n", RDX_BLK_MIN_POOL_PAGES);
		goto out;
	}

	rdx_blk->main_bdev = blkdev_get_by_path(main_bdev_path, FMODE_READ | FMODE_WRITE, rdx_blk);
	if(IS_ERR(rdx_blk->main_bdev)){
		pr_debug("Cannot find bdev: %s \n", main_bdev_path);
		ret = -EINVAL;
		goto out;
	}

	pr_debug("Set main bdev to %s\n", main_bdev_path);

	rdx_blk->aux_bdev = blkdev_get_by_path(aux_bdev_path, FMODE_READ | FMODE_WRITE, rdx_blk);
	if(IS_ERR(rdx_blk->aux_bdev)){
		pr_debug("Cannot find bdev: %s \n", aux_bdev_path);
		ret = -EINVAL;
		goto out;
	}

	pr_debug("Set aux bdev to %s\n", aux_bdev_path);
	rdx_blk->sectors = get_capacity(rdx_blk->main_bdev->bd_disk);

	rdx_blk->queue = blk_alloc_queue_node(GFP_KERNEL, home_node);
	if(!rdx_blk->queue){
		pr_debug("Cannot allocate queue for %s\n", RDX_BLKDEV_NAME);
		ret = -ENOMEM;
		goto out;
	}

	blk_queue_make_request(rdx_blk->queue, rdx_blk_make_request);
	rdx_blk->queue->queuedata = rdx_blk;
	blk_queue_logical_block_size(rdx_blk->queue, blocksize);
	blk_queue_physical_block_size(rdx_blk->queue, blocksize);

	gd = alloc_disk_node(rdx_minor, home_node);
	if(!gd){
		pr_debug("Cannot allocate gendisk for %s\b", RDX_BLKDEV_NAME);
		ret = -ENOMEM;
		goto out;
	}
	rdx_blk->gd = gd;
	gd->private_data = rdx_blk;
	gd->queue = rdx_blk->queue;
	gd->major = rdx_major;
	gd->first_minor = rdx_minor;
	rdx_minor++;
	gd->flags |= GENHD_FL_EXT_DEVT | GENHD_FL_SUPPRESS_PARTITION_INFO;
	gd->fops = &rdx_blk_fops;
	snprintf(gd->disk_name, DISK_NAME_LEN, "%s", rdx_blk->name);
	set_capacity(gd, rdx_blk->sectors);

	add_disk(gd);
	pr_debug("Disk %s added on node %d, rdx_blk=%p\n", gd->disk_name, home_node, rdx_blk);



	return 0;

out:
	rdx_destroy_dev();
	return ret;
}

static int __init rdx_blk_init(void)
{
	int ret = 0;

	printk("Main storage path: %s, buffer path: %s\n", main_bdev_path, aux_bdev_path);
	mutex_init(&lock);

    rdx_request_cachep = kmem_cache_create("rdx_request_cachep", sizeof(struct rdx_request),
    		0, 0,  NULL);

    if (!rdx_request_cachep) {
        pr_debug( "Could not allocate rdx_request_cachep!\n" ) ;
        ret = -ENOMEM;
    }

	rdx_major = register_blkdev(0, RDX_BLKDEV_NAME);
	if(rdx_major < 0){
		return rdx_major;
	}

	return ret;
}


static void __exit rdx_blk_exit(void)
{
	if (rdx_blk != NULL){
		rdx_destroy_dev();
	}

    if (rdx_request_cachep){
        kmem_cache_destroy(rdx_request_cachep);
    }

	unregister_blkdev(rdx_major, RDX_BLKDEV_NAME);
	pr_debug("%s unregistered, exit.\n", RDX_BLKDEV_NAME);
}

int __set_cur_cmd(const char *str, struct kernel_param *kp){
	pr_debug("Got command \"%s\" in rp_msb control\n", str);
	if(!strcmp(str, "create\n")){
		rdx_blk_create_dev();
	}
	if(!strcmp(str, "destroy\n")){
		rdx_destroy_dev();
	}

	return 0;
}

MODULE_PARM_DESC(control, "cmd to execute");
module_param_call(control, __set_cur_cmd, NULL, NULL, S_IRUGO | S_IWUSR);

module_init(rdx_blk_init);
module_exit(rdx_blk_exit);

MODULE_AUTHOR("AM");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");