/*
 * rdx_blk_service.c
 *
 *  Created on: 12 окт. 2017 г.
 *      Author: alekseym
 */

#include <linux/kernel.h>
#include <linux/wait.h>

#include "rdx_blk.h"
#include "rdx_blk_request.h"
#include "rdx_blk_range.h"

int generate_evict_bio(uint64_t first_sect, int sectors, struct rdx_blk *dev, struct msb_range *range){
	struct bio *bio;
	struct rdx_request *req;
	uint64_t pages, offset, bytes, xferred, len;
	size_t i;
	char *data_addr;

	bytes = sectors * KERNEL_SECT_SIZE;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	bio = bio_alloc(GFP_NOIO, pages);
	if (!bio) {
		pr_debug("Cannot allocate bio\n");
		return -ENOMEM;
	}
	bio->bi_iter.bi_sector = first_sect;
	bio->bi_bdev = dev->main_bdev;
	bio->bi_opf = REQ_OP_READ;

	req = __create_req(bio, dev, RDX_REQ_EVICT_R);
	if(!req){
		pr_debug("for bio=%p cannot allocate req\n", bio);
		return -ENOMEM;
	}
	req->range = range;
	req->buf = kmalloc(bytes, GFP_KERNEL);

	if(!req->buf){
		pr_debug("Cannot allocate buf for req=%p\n", req);
		kmem_cache_free(rdx_request_cachep, req);
		bio_put(bio);
		return -ENOMEM;
	}

	offset = (uint64_t)((long)req->buf % PAGE_SIZE);

	bio->bi_private = req;

	data_addr = req->buf;
	xferred = 0;
	for (i = 0; i < pages; i++) {
		if (offset + bytes - xferred < PAGE_SIZE)
			len = bytes - xferred;
		else
			len = PAGE_SIZE - offset;

		bio_add_page(bio, virt_to_page(data_addr), len, offset);
		offset = 0;
		data_addr += len;
		xferred += len;
	}
	req->sectors = bio_sectors(bio);

	pr_debug("Generate bio=%p, req=%p, dev=%s, first_sect=%lu, sectors=%d\n",
			bio, req, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
	pr_debug(" bio=%p, bio->remaining=%d bio->bi_cnt=%d\n",bio, atomic_read(&bio->__bi_remaining), atomic_read(&bio->__bi_cnt));
	submit_bio(bio);
	return 0;
}

//returns the offset such that commands to evict data before this offset has been submited
uint64_t evict_range(struct msb_data *data, struct msb_range *range, uint64_t last_offset){
	int first_bit = 0, next_zero_bit = 0, cur_bit = 0;
	uint64_t first_sector;
	int sectors;
	uint64_t offset = last_offset;
	int res = 0;

	pr_debug("Start evicting range range=%p start_lba_main=%llu, start_lba_aux=%llu, offset=%llu\n",
					range, range->start_lba_main, range->start_lba_aux, offset);

	cur_bit = lba2bit(range, range->start_lba_main + offset);
	first_bit = find_next_bit(range->bitmap, data->range_bitmap_size, cur_bit);
	next_zero_bit = find_next_zero_bit(range->bitmap, data->range_bitmap_size, first_bit);

	pr_debug("for range = %p, cur_bit = %d, first_bit = %d, next_zero_bit = %d\n",
			range, cur_bit, first_bit, next_zero_bit);

	while(first_bit != data->range_bitmap_size){
		first_sector = bit2lba(range, first_bit);
		sectors = bit2lba(range, next_zero_bit) - first_sector;

		if(sectors > BIO_MAX_PAGES * PAGE_SIZE / KERNEL_SECT_SIZE){
			sectors = BIO_MAX_PAGES * PAGE_SIZE / KERNEL_SECT_SIZE;
		}

		pr_debug("Generate evict bio first_sect=%llu, len=%d\n", first_sector, sectors);
		//res = __create_io(data, range, first_sector, sectors, WRITE);
		res = generate_evict_bio(first_sector, sectors, data->dev, range);
		if(res != 0){
			pr_debug("Cannot create evict io while evicting range=%p", range);
			return offset;
		}

		atomic_inc(&data->num_evict_cmd);

		pr_debug("Current number of evict cmd = %d of %llu\n",
				atomic_read(&data->num_evict_cmd), data->max_num_evict_cmd);
		cur_bit = lba2bit(range, first_sector + sectors);
		first_bit = find_next_bit(range->bitmap, data->range_bitmap_size, cur_bit);
		next_zero_bit = find_next_zero_bit(range->bitmap, data->range_bitmap_size, first_bit);

		pr_debug("for range = %p, cur_bit = %d, first_bit = %d, next_zero_bit = %d\n",
				range, cur_bit, first_bit, next_zero_bit);

		if(atomic_read(&data->num_evict_cmd) >= data->max_num_evict_cmd){
			//check if something left in this range
			if(first_bit == data->range_bitmap_size){ //nothing left
				pr_debug("Max allowed number of evict cmd achieved for range=%p, returned offset=%llu, finish with this range\n",
						range, data->range_bitmap_size);
				return data->range_size_sectors;
			} else{ // something left in this range and it will be evicted later
				offset = first_sector + sectors - range->start_lba_main;
				pr_debug("Max allowed number of evict cmd achieved for range=%p, returned offset=%llu\n",
						range, offset);
				return offset;
			}
		}
	}
	pr_debug("All eviction commands to range=%p, start_lba_main=%llu, start_lba_aux=%llu has been submited\n",
			range, range->start_lba_main, range->start_lba_aux);
	return data->range_size_sectors;
}

void evict_to_main(struct msb_data* data){
	struct rb_node *tree_node;
	struct rb_root *tree_root;
	struct msb_range *range;
	uint64_t offset = 0;
	bool eviction_canceled = false;

	pr_debug("Migration started. Lock tree_lock...\n");
	tree_root = &data->ranges;

	read_lock_bh(&data->tree_lock);
		tree_node = rb_first(tree_root);
	read_unlock_bh(&data->tree_lock);

	pr_debug("Unlock tree_lock\n");

	while(tree_node != NULL && !eviction_canceled){
		offset = 0;
		pr_debug("Current rb node to evict = %p\n", tree_node);
		range = container_of(tree_node, struct msb_range, tree_node);

		//choose  next rb tree node in case we delete this node after eviction
		read_lock_bh(&data->tree_lock);
			tree_node = rb_next(tree_node);
		read_unlock_bh(&data->tree_lock);

		//if there are active rw commands to this range then skip it
		// 0 mens we don't have any active cmd

		if(atomic_dec_and_test(&range->ref_cnt)){
			pr_debug("Mark range=%p for eviction start_lba_main=%llu, start_lba_aux=%llu \n",
							range, range->start_lba_main, range->start_lba_aux);

			while(offset != data->range_size_sectors){
				pr_debug("Service is going to sleep until we can generate new evict cmd\n");
				wait_event_interruptible(data->wq_evict_cmd, (atomic_read(&data->num_evict_cmd) < data->max_num_evict_cmd));

				pr_debug("Service Woken up. Current evict cmd num=%d , start evicting range %p since offset=%llu\n",
						atomic_read(&data->num_evict_cmd), range, offset);
				offset = evict_range(data, range, offset);
			}
		} else {
			atomic_inc(&range->ref_cnt); //return to previous value of ref_cnt
			pr_debug("range=%p start_lba_main=%llu start_lba_aux=%llu is busy (ref_cnt=%d). Got to the next range in tree\n",
					range, range->start_lba_main, range->start_lba_aux, atomic_read(&range->ref_cnt));
		}

		if(test_bit(MSB_CANCEL_EVICTION, &data->flags)){
			pr_debug("Someone canceled eviction. Break it.\n");
			eviction_canceled = true;

		}
	}

	pr_debug("End of rb_tree achieved\n");
	return;
}

static void __start_evict(struct work_struct *ws){
	struct msb_data *data = container_of(ws, struct msb_data, work);

	pr_debug("Start data eviction\n");
	clear_bit(MSB_CANCEL_EVICTION, &data->flags);
	set_bit(MSB_EVICTION_IN_PROGRESS, &data->flags);
	evict_to_main(data);
	clear_bit(MSB_EVICTION_IN_PROGRESS, &data->flags);
	pr_debug("Finish data eviction. Next will start soon\n");

	wake_up_interruptible(&data->wq_evict_cmd);

	if(!test_bit(MSB_CANCEL_EVICTION, &data->flags)){
		mod_timer(&data->dev->evict_timer, jiffies + msecs_to_jiffies(3 * 1000));
	}
}

void start_evict_service(struct rdx_blk *dev)
{
    mod_timer(&dev->evict_timer, jiffies + msecs_to_jiffies(1000));
    pr_debug("Eviction service started\n");
}

int stop_evict_service(struct rdx_blk *dev)
{
    struct msb_data *data = dev->data;

    del_timer_sync(&dev->evict_timer);

    set_bit(MSB_CANCEL_EVICTION, &data->flags);

    pr_debug("Eviction in progress = %d\n", test_bit(MSB_EVICTION_IN_PROGRESS, &data->flags));
    pr_debug("Service going to sleep until all eviction commands done \n");
    wait_event_interruptible(data->wq_evict_cmd,
    		(test_bit(MSB_EVICTION_IN_PROGRESS, &data->flags) == 0) && (atomic_read(&data->num_evict_cmd) == 0));
    pr_debug("Service awoke after achieving number of evict cmd == 0 and eviction stopped\n");

    pr_debug("Eviction stopped.\n");
    return 0;
}


void __evict_timer_handler(unsigned long data_ptr)
{
    struct msb_data *data = (struct msb_data *)data_ptr;

    pr_debug("MSB timer handler called\n");

    INIT_WORK(&data->work, __start_evict);
    queue_work(rdx_blk_evict_wq, &data->work);

//    mod_timer(&vs->timer, jiffies + msecs_to_jiffies(atomic_read(&vs->delay)));
}
