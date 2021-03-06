#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <trace/events/block.h>
#include <linux/preempt.h>

#include "rdx_blk.h"
#include "rdx_blk_request.h"
#include "rdx_blk_filter.h"
#include "rdx_blk_range.h"

static void __evict_write(struct work_struct *ws){
	struct  msb_range *range;
	uint64_t offset;
	struct rdx_request *req = container_of(ws, struct rdx_request, work);
	struct bio *usr_bio = req->usr_bio;

	//trace_block_bio_complete(bdev_get_queue(usr_bio->bi_bdev), usr_bio, req->err);

	pr_debug("req=%p bio=%p finished. bi_iter: bi_sector=%lu, bi_size=%d, bi_idx=%d, bi_bvec_done=%d\n",
			req, usr_bio, usr_bio->bi_iter.bi_sector, usr_bio->bi_iter.bi_size,
			usr_bio->bi_iter.bi_idx, usr_bio->bi_iter.bi_bvec_done);

	range = req->range;
	offset = req->first_sector - range->start_lba_aux;
	req->first_sector = range->start_lba_main + offset;

	usr_bio->bi_bdev = req->dev->main_bdev;
	usr_bio->bi_iter.bi_sector = range->start_lba_main + offset;
	usr_bio->bi_iter.bi_size = req->sectors << 9;
	usr_bio->bi_iter.bi_idx = 0;
	usr_bio->bi_iter.bi_bvec_done = 0;
	usr_bio->bi_opf = REQ_OP_WRITE;

	req->type = RDX_REQ_EVICT_W;

	atomic_set(&req->ref_cnt, 1);
	pr_debug("Remap bio=%p : dir=%s, dev=%s, first_sect=%lu, sectors=%d\n",
			usr_bio, bio_data_dir(usr_bio) == WRITE ? "W" : "R", usr_bio->bi_bdev->bd_disk->disk_name,
			bio_first_sector(usr_bio), bio_sectors(usr_bio));
	pr_debug("bio=%p, bio->remaining=%d bio->bi_cnt=%d\n", usr_bio, atomic_read(&usr_bio->__bi_remaining), atomic_read(&usr_bio->__bi_cnt));
	submit_bio(usr_bio);
}

static void __evict_write_end(struct work_struct *ws){
	struct  msb_range *range;
	uint64_t offset;
	unsigned long bit_pos;
	struct rdx_request *req = container_of(ws, struct rdx_request, work);
	struct bio *usr_bio = req->usr_bio;
	struct msb_data *data;

	//trace_block_bio_complete(bdev_get_queue(usr_bio->bi_bdev), usr_bio, req->err);

	pr_debug("req=%p bio=%p finished. bi_iter: bi_sector=%lu, bi_size=%d, bi_idx=%d, bi_bvec_done=%d\n",
			req, usr_bio, usr_bio->bi_iter.bi_sector, usr_bio->bi_iter.bi_size,
			usr_bio->bi_iter.bi_idx, usr_bio->bi_iter.bi_bvec_done);

	range = req->range;
	pr_debug("Clear mask in range = %p req=%p, first_sect=%lu, sectors=%lu\n",
			range, req, req->first_sector, req->sectors);
	data = range->data;
	pr_debug("in interrupt %lu, in irq=%lu, in soft_irq=%lu\n", in_interrupt(), in_irq(),in_softirq() );

	write_lock(&range->lock);
		msb_clearbits_in_range(range, req->first_sector, req->sectors);
		bit_pos = find_first_bit(range->bitmap, data->range_bitmap_size);
		pr_debug("In range=%p position of nonzero bit = %lu \n", range, bit_pos);
	write_unlock(&range->lock);

	atomic_dec(&range->data->num_evict_cmd);
	wake_up_interruptible(&range->data->wq_evict_cmd);

	if(bit_pos == data->range_bitmap_size){
		msb_range_delete(range);
	}

	usr_bio->bi_end_io = req->__usr_bio_end_io;
	usr_bio->bi_private = req->usr_bio_private;
	usr_bio->bi_error = req->err;

	pr_debug("For req=%p restore usr_bio=%p parameters and end it\n", req, usr_bio);

	pr_debug("bio=%p, bio->remaining=%d bio->bi_cnt=%d\n",usr_bio,  atomic_read(&usr_bio->__bi_remaining), atomic_read(&usr_bio->__bi_cnt));
	bio_put(usr_bio);
	if(req->buf){
		pr_debug("free req=%p buf=%p\n", req, req->buf);
		kfree(req->buf);
	}
	kmem_cache_free(rdx_request_cachep, req);
}

void __req_put(struct rdx_request *req)
{
	struct msb_range *range;
	struct msb_data *data;
	unsigned long bit_pos;
	pr_debug("Before dec_and_test for req=%p req->ref->cnt=%d\n", req, atomic_read(&req->ref_cnt));

	switch(req->type){
	case RDX_REQ_RW:
		if (atomic_dec_and_test(&req->ref_cnt)) {
			struct bio *usr_bio = req->usr_bio;

			trace_block_bio_complete(bdev_get_queue(usr_bio->bi_bdev), usr_bio, req->err);

			usr_bio->bi_end_io = req->__usr_bio_end_io;
			usr_bio->bi_private = req->usr_bio_private;
			usr_bio->bi_error = req->err;

			pr_debug("For req=%p restore usr_bio=%p parameters and end it\n", req, usr_bio);

			if(req->range != NULL){
				//release range if it were intersections
				atomic_dec(&req->range->ref_cnt);
				pr_debug("request %p ended for range=%p ref_cnt=%d\n",
						req, req->range, atomic_read(&req->range->ref_cnt));
			}
			bio_endio(usr_bio);
			kmem_cache_free(rdx_request_cachep, req);
		}
		break;
	case RDX_REQ_EVICT_R:
		if (atomic_dec_and_test(&req->ref_cnt)) {
			pr_debug("Init work struct after end evict read for req =%p\n", req);
		    INIT_WORK(&req->work, __evict_write);
		    queue_work(rdx_blk_wq, &req->work);
		}

		break;
	case RDX_REQ_EVICT_W:
		if (atomic_dec_and_test(&req->ref_cnt)) {
			pr_debug("Init work struct after finish evict write for req =%p\n", req);
		    INIT_WORK(&req->work, __evict_write_end);
		    queue_work(rdx_blk_wq, &req->work);
		}
		break;
	}
}

static void __end_transfer(struct bio *bio)
{
	struct rdx_request *req = bio->bi_private;

	if (!req->err)
		req->err = bio->bi_error;

	pr_debug("end_io for bio=%p\n", bio);
	__req_put(req);
}

// request covers bio to only one range
blk_qc_t rdx_blk_make_request(struct request_queue *q, struct bio *bio){
	struct rdx_blk *dev = q->queuedata;

	if (bio_sectors(bio) == 0) {
		bio->bi_error = 0;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	if(bio_data_dir(bio) == WRITE){
		msb_write_filter(dev->data, bio, false);
	} else { // READ
		msb_read_filter(dev->data, bio, false);
	}

	return BLK_QC_T_NONE;
}


struct rdx_request *__create_req(struct bio *bio, struct rdx_blk *dev, enum rdx_req_type type){
	struct rdx_request *req;

	req = kmem_cache_zalloc(rdx_request_cachep, GFP_ATOMIC);
	if (!req) {
		pr_debug("Cannot allocate request\n");
		bio_io_error(bio);
		return NULL;
	}

	req->first_sector = bio_first_sector(bio);
	req->sectors = bio_sectors(bio);
	req->dev = dev;
	req->rw = bio_data_dir(bio);
	req->type = type;
	req->buf = NULL;
	INIT_LIST_HEAD(&req->list);

	//save info about initial bio
	req->usr_bio = bio;
	req->usr_bio_private = bio->bi_private;
	req->__usr_bio_end_io = bio->bi_end_io;


	bio->bi_private = req;
	bio->bi_end_io = __end_transfer;
	atomic_set(&req->ref_cnt, 1);
	return req;
}
