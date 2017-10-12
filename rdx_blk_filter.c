/*
 * rdx_blk_filter.c
 *
 *  Created on: 10 окт. 2017 г.
 *      Author: alekseym
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/bitmap.h>
#include <linux/bio.h>

#include "rdx_blk.h"
#include "rdx_blk_hashtable.h"
#include "rdx_blk_range.h"
#include "rdx_blk_request.h"

//return 0 for successful redirection and -EBUSY if range is migrating
int __redirect_req(struct rdx_request *req, struct msb_range *range, struct msb_data *data){
	uint64_t offset;
	int res = 0;
	struct bio *bio = req->usr_bio;

	pr_debug("req=%p, usr_bio=%p, dir=%s, first_sec=%lu, sectors=%lu",
			req, req->usr_bio, bio_data_dir(bio) == WRITE ? "W" : "R", req->first_sector, req->sectors);

	if(bio_data_dir(bio) == WRITE){
		write_lock_bh(&range->lock);
		{
			//if range is involved in migration process then retry this command later
			if(atomic_inc_not_zero(&range->ref_cnt) == 0){
				pr_debug("Range %p main_lba=%llu is migrating, return BUSY for bio=%p\n",
						range, range->start_lba_main, bio);
				res = -EBUSY;
			} else { //range is ok then correct bits in  this range and redirect bio
				//TODO : move this code to msb_intersect range
				msb_setbits_in_range(range, bio_first_sector(bio), bio_sectors(bio));

				offset = bio_first_sector(bio) - range->start_lba_main;
				bio->bi_iter.bi_sector = range->start_lba_aux + offset;

				bio->bi_bdev = data->dev->aux_bdev;
				req->range = range;
				submit_bio(bio);

			    pr_debug("For range=%p ref_cnt=%d\n",
			    		range, atomic_read(&range->ref_cnt));
			}
		}
		write_unlock_bh(&range->lock);
	}// dir == READ
	else{
		read_lock_bh(&range->lock);
		{
			//if range is involved in migration process then retry this command later
			if(atomic_inc_not_zero(&range->ref_cnt) == 0){
				pr_debug("Range %p main_lba=%llu is migrating, return BUSY for bio=%p\n",
						range, range->start_lba_main, bio);
				res = -EBUSY;
			} else { //range is ok then intersect scmd
			    pr_debug("For range=%p ref_cnt =%d\n",
			    		range, atomic_read(&range->ref_cnt));
				msb_intersect_range(data, range, req);

				//if we found intersections then ref_cnt was increased
				//if not then  we have to release this range
				atomic_dec(&range->ref_cnt);
			    pr_debug("For range=%p ref_cnt =%d\n",
			    		range, atomic_read(&range->ref_cnt));
			}
		}
		read_unlock_bh(&range->lock);
	}
	return res;
}

int filter_write_req(struct msb_data *data, struct rdx_request *req){
	int res = 0;
	struct msb_range *range;
	uint64_t start_lba_main;

	start_lba_main = get_start_lba(req->first_sector, data);
	range = msb_hashtable_get_range(data->ht, start_lba_main);
	if(range == NULL){
		//didn't find it
		pr_debug("There is no range for req=%p bio=%p, first_sector=%lu, start_lba_main=%llu\n",
				req, req->usr_bio, req->first_sector, start_lba_main);
		pr_debug("for req=%p usr_bio = %p\n", req, req->usr_bio);
		range = msb_range_create(data, start_lba_main);
		pr_debug("for req=%p usr_bio = %p\n", req, req->usr_bio);
		if(!range){ //failed to create range
			pr_debug("Failed to create range, not redirecting req=%p\n", req);
			res = -ENOMEM;
			return res;
		}

		pr_debug("for req=%p usr_bio = %p\n", req, req->usr_bio);
		//redirect bio according to range mapping
		res = __redirect_req(req, range, data);

		msb_hashtable_add_range(data->ht, range);

		//insert after redirection so that we dont start eviction of this range before actual redirection
		write_lock_bh(&data->tree_lock);
			msb_range_tree_insert(data, range);
		write_unlock_bh(&data->tree_lock);

	} else {
		//we found range for this scmd
		//redirect scmd according to range mapping
		res = __redirect_req(req, range, data);
	}
	return res;
}

/**
 * Apply the msb write filter to @cmd.
 * @param vf - the volume filter;
 * @param cmd - the RVM command.
 * @return 0 for success, or error code.
 */
int msb_write_filter(struct msb_data *data, struct bio *bio)
{
    int res = 0;
    struct msb_hashtable *ht;
    uint64_t first_sector, sectors;
    uint64_t offset;	/*offset in current range*/
    uint32_t slen; 		/* command length fitting in a range */
    struct bio *split;
    uint64_t msb_range_size_sectors = data->range_size_sectors;

    struct rdx_request *req;

    //check whether data is being deleted
//    if (test_bit(MSB_FLAG_DELETING, &data->flags))
//        return 0;

    pr_debug("IN : bio=%p, dev=%s, first_sect=%lu, len=%d, \n",
    		bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));

    ht = data->ht;

    //TODO: do not handle data migration cmd
//    if (cmd->client == &msb_service_client)
//        return res;

    first_sector = bio_first_sector(bio);
    sectors = bio_sectors(bio);

    msb_lock_buckets(ht, first_sector, sectors, WRITE);

    //go through all ranges covered by this bio
    do{
    	offset = bio_first_sector(bio) % msb_range_size_sectors;
    	slen = msb_range_size_sectors - offset; //sectors fits in current range

    	if(slen < bio_sectors(bio)){
    		split = bio_split(bio, slen, GFP_NOIO, data->dev->split_bioset);
    		pr_debug("split_bio(%p), bdev=%s, first_sector=%lu, size=%d\n",
    				split, split->bi_bdev->bd_disk->disk_name, bio_first_sector(split), bio_sectors(split));
    		bio_chain(split, bio);
    	} else{
    		split = bio;
    	}

    	pr_debug("before __create_req split = %p\n", split);
    	req = __create_req(split, data->dev);
		if(req == NULL){
			pr_debug("cannot allocate req for bio=%p\n", split);
			bio_io_error(bio);
			res = -ENOMEM;
			break;
		}

		pr_debug("for bio=%p created req=%p first_sect=%lu, sectors=%lu\n",
						split, req, req->first_sector, req->sectors);
		res = filter_write_req(data, req);
		if(res == -ENOMEM){
			bio->bi_bdev = data->dev->main_bdev;
			submit_bio(bio);
		}
    }while(split != bio);

    msb_unlock_buckets(ht, first_sector, sectors, WRITE);

    pr_debug("OUT: bio=%p, dev=%s, first_sect=%lu, len=%d \n",
    		bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
    return res;
}

//void __mark_scmd_for_caching(struct rvm_subcommand *scmd, struct msb_range *range){
//
//	scmd->priv = &range->scpriv;
//	atomic_inc(&range->ref_cnt); //so that we dont start eviction of this range
//	atomic_inc(&range->data->num_caching_cmd);
//	pr_debug("For scmd=%p lba=%llu, len=%d marked for caching to range=%p range->ref_cnt=%d, num_caching_scmd=%d of %d\n",
//			scmd, scmd->lba, scmd->len, range, atomic_read(&range->ref_cnt),
//			atomic_read(&range->data->num_caching_cmd), MSB_MAX_CACHING_CMD);
//}

int filter_read_req(struct msb_data *data, struct rdx_request *req){
	int res = 0;
	struct msb_range *range;
	uint64_t start_lba_main;

	start_lba_main = get_start_lba(req->first_sector, data);
	range = msb_hashtable_get_range(data->ht, start_lba_main);

	if(range != NULL){
		pr_debug("For req=%p, first_sect=%lu, req->sectors=%lu, req->dev=%s found range=%p, start_lba_main=%llu, start_lba_aux=%llu\n",
				req, req->first_sector, req->sectors, req->dev->name, range, range->start_lba_main, range->start_lba_aux);

		res = __redirect_req(req, range, data);
	}
	else {
		pr_debug("For req=%p, first_sect=%lu, req->sectors=%lu, req->dev=%s there is no range in HT\n",
				req, req->first_sector, req->sectors, req->dev->name);
		//no range hence goes to main
		req->usr_bio->bi_bdev = data->dev->main_bdev;
		submit_bio(req->usr_bio);
	}
	return res;
}

/**
 * Apply the MSB read filter to @cmd.
 * @param vf - the volume filter;
 * @param cmd - the RVM command.
 * @return 0 for success, or error code.
 */
int msb_read_filter(struct msb_data *data, struct bio *bio)
{
	int res = 0;
	struct msb_hashtable *ht;
	uint64_t first_sector, sectors;
	uint64_t offset;	/*offset in current range*/
	uint32_t slen; 		/* command length fitting in a range */
	struct bio *split;
	uint64_t msb_range_size_sectors = data->range_size_sectors;

	struct rdx_request *req;

	//check whether data is being deleted
//    if (test_bit(MSB_FLAG_DELETING, &data->flags))
//        return 0;

	pr_debug("IN : bio=%p, dev=%s, first_sect=%lu, len=%d, \n",
			bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));

	ht = data->ht;

	//TODO: do not handle data migration cmd
//    if (cmd->client == &msb_service_client)
//        return res;

	first_sector = bio_first_sector(bio);
	sectors = bio_sectors(bio);

	msb_lock_buckets(ht, first_sector, sectors, READ);

	//go through all ranges covered by this bio
	do{
		offset = bio_first_sector(bio) % msb_range_size_sectors;
		slen = msb_range_size_sectors - offset; //sectors fits in current cange

		if(slen < bio_sectors(bio)){
			split = bio_split(bio, slen, GFP_NOIO, data->dev->split_bioset);
			pr_debug("split_bio(%p), bdev=%s, first_sector=%lu, size=%d\n",
					split, split->bi_bdev->bd_disk->disk_name, bio_first_sector(split), bio_sectors(split));
			bio_chain(split, bio);
		} else{
			split = bio;
		}
    	pr_debug("before __create_req split = %p\n", split);
		req = __create_req(split, data->dev);

		if(req == NULL){
			pr_debug("cannot allocate req for bio=%p\n", split);
			bio_io_error(bio);
			res = -ENOMEM;
			break;
		}
		printk("for bio=%p created req=%p first_sect=%lu, sectors=%lu\n",
						split, req, req->first_sector, req->sectors);
		res = filter_read_req(data, req);
		if(!res){
			//?
		}
	}while(split != bio);

	msb_unlock_buckets(ht, first_sector, sectors, READ);

	pr_debug("OUT: bio=%p, dev=%s, first_sect=%lu, len=%d, \n",
			bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
	return res;
}
