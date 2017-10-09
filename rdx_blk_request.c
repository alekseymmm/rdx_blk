#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <trace/events/block.h>

#include "rdx_blk.h"
#include "rdx_blk_request.h"

static void __req_put(struct rdx_request *req)
{
	pr_debug("Before dec_and_test for req=%p req->ref->cnt=%d\n", req, atomic_read(&req->ref_cnt));

	if (atomic_dec_and_test(&req->ref_cnt)) {
		struct bio *usr_bio = req->usr_bio;

		trace_block_bio_complete(bdev_get_queue(usr_bio->bi_bdev), usr_bio, req->err);

		usr_bio->bi_end_io = req->__usr_bio_end_io;
		usr_bio->bi_private = req->usr_bio_private;
		usr_bio->bi_error = req->err;

		pr_debug("For req=%p restore usr_bio=%p parameters and end it\n", req, usr_bio);
		bio_endio(usr_bio);
		kmem_cache_free(rdx_request_cachep, req);
	}
}

static void __end_transfer(struct bio *bio)
{
	struct rdx_request *req = bio->bi_private;

	if (!req->err)
		req->err = bio->bi_error;

	__req_put(req);
}


static void __start_transfer(struct rdx_request *req)
{
	struct bio *bio = req->usr_bio;
	struct bio *split;

	if(bio_sectors(bio) > 4096){
		split = bio_split(bio, 4096, GFP_NOIO, rdx_blk->split_bioset);
		if(!split){
			pr_debug("Cannot split\n");
			req->err = -ENOMEM;
			__req_put(req);
		}
		else{
			bio_chain(split, bio);
			split->bi_bdev = rdx_blk->aux_bdev;

			pr_debug("split_bio(%p), bdev=%s, first_sector=%lu, size=%d\n",
					split, split->bi_bdev->bd_disk->disk_name, bio_first_sector(split), bio_sectors(split));
			submit_bio(split);
		}
	}

	bio->bi_bdev = rdx_blk->main_bdev;
	bio->bi_private = req;
	bio->bi_end_io = __end_transfer;

	pr_debug("bio(%p), bdev=%s, first_sector=%lu, size=%d\n",
			bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
	submit_bio(bio);
}

blk_qc_t rdx_blk_make_request(struct request_queue *q, struct bio *bio){
	struct rdx_blk *dev = q->queuedata;
	struct rdx_request *req;

	if (!bio_sectors(bio)) {
		bio->bi_error = 0;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	req = kmem_cache_zalloc(rdx_request_cachep, GFP_KERNEL);
	if (!req) {
		pr_debug("Cannot allocate request\n");
		bio_io_error(bio);
		return BLK_QC_T_NONE;
	}

	req->first_sector = bio_first_sector(bio);
	req->sectors = bio_sectors(bio);
	req->dev = dev;
	req->rw = bio_data_dir(bio);
	//store info about initial bio
	req->usr_bio = bio;
	req->usr_bio_private = bio->bi_private;
	req->__usr_bio_end_io = bio->bi_end_io;

	atomic_set(&req->ref_cnt, 1);

	__start_transfer(req);
	return BLK_QC_T_NONE;
}
