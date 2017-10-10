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
int __redirect_bio(struct bio *bio, struct msb_range *range, struct msb_data *data){
	uint64_t offset;
	int res = 0;

	if(bio_data_dir(bio) == WRITE){
		write_lock_bh(&range->lock);
		{
			//if range is involved in migration process then retry this command later
			if(atomic_inc_not_zero(&range->ref_cnt) == 0){
				pr_debug("Range %p main_lba=%llu is migrating, return BUSY for bio=%p\n",
						range, range->start_lba_main, bio);
				res = -EBUSY;
			} else { //range is ok then correct bits in  this range and redirect bio
				msb_setbits_in_range(range, bio_first_sector(bio), bio_sectors(bio));

				offset = bio_first_sector(bio) - range->start_lba_main;
				bio->bi_iter.bi_sector = range->start_lba_aux + offset;

				bio->bi_bdev = data->dev->aux_bdev;
				bio_submit(bio);

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
				msb_intersect_range(data, range, scmd);

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

	start_lba_main = get_start_lba(req->first_sector);
	range = msb_hashtable_get_range(data->ht, start_lba_main);
	if(range == NULL){
		//didn't find it
		pr_debug("There is no range for req=%p bio=%p, first_sector=%lu, start_lba_main=%llu\n",
				req, req->usr_bio, req->first_sector, start_lba_main);

		range = msb_range_create(data, start_lba_main);

		if(!range){ //failed to create range
			pr_debug("Failed to create range, not redirecting req=%p\n", req);
			res = -ENOMEM;
			return res;
		}

		msb_hashtable_add_range(data->ht, range);

		req->range = range;
		//redirect bio according to range mapping
		res = __redirect_bio(req->usr_bio, range, data);

		//insert after redirection so that we dont start eviction of this range before actual redirection
		write_lock_bh(&data->tree_lock);
			msb_range_tree_insert(data, range);
		write_unlock_bh(&data->tree_lock);

	} else {
		//we found range for this scmd
		//redirect scmd according to range mapping
		res = __redirect_bio(req->usr_bio, range, data);
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
    uint64_t first_sector, sectors, end_sect;
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

    	req = __create_req(split, data->dev);
		if(req == NULL){
			pr_debug("cannot allocate req for bio=%p\n", split);
			bio_io_error(bio);
			res = -ENOMEM;
			break;
		}
		res = filter_write_req(data, req);
		if(!res){
			//?
		}
    }while(split == bio);

    msb_unlock_buckets(ht, first_sector, sectors, WRITE);

    pr_debug("OUT: bio=%p, dev=%s, first_sect=%lu, len=%d, \n",
    		bio, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
    return res;
}

void __mark_scmd_for_caching(struct rvm_subcommand *scmd, struct msb_range *range){

	scmd->priv = &range->scpriv;
	atomic_inc(&range->ref_cnt); //so that we dont start eviction of this range
	atomic_inc(&range->data->num_caching_cmd);
	pr_debug("For scmd=%p lba=%llu, len=%d marked for caching to range=%p range->ref_cnt=%d, num_caching_scmd=%d of %d\n",
			scmd, scmd->lba, scmd->len, range, atomic_read(&range->ref_cnt),
			atomic_read(&range->data->num_caching_cmd), MSB_MAX_CACHING_CMD);
}

/**
 * Apply the MSB read filter to @cmd.
 * @param vf - the volume filter;
 * @param cmd - the RVM command.
 * @return 0 for success, or error code.
 */
int msb_read_filter(struct rvm_volume_filter *vf, struct rvm_command *cmd)
{
    int res = 0;

    struct rvm_subcommand *scmd;
    struct msb_data *data;
    struct msb_hashtable *ht;

    rdx_check_ptrr(cmd, HRM_RCMD, -EINVAL);

    data = vf_get_data(vf);
    rdx_check_ptrr(data, HRM_MSBD, -EINVAL);
//    if (test_bit(TIER_FLAG_DELETING, &data->flags))
//        return 0;
    ht = data->ht;

    pr_debug("MSB read_filter called, cmd=%p lba=%llu len=%d, client=%s\n",
    		cmd, cmd->lba, cmd->len,  cmd->client->name);

    list_for_each_entry(scmd, &cmd->scmd_list, list){
    	pr_debug("IN cmd=%p [%s] scmd=%p : (vol=%s, lba=%llu, len=%d)\n",
    			cmd, cmd->dir == WRITE ? "W" : "R", scmd,  scmd->vol->name, scmd->lba, scmd->len);
    }

    if(read_caching_enabled){ //we can decide to create new range, so we have to get write_lock
    	msb_lock_buckets(ht, cmd->lba, cmd->len, WRITE);
    } else {
    	msb_lock_buckets(ht, cmd->lba, cmd->len, READ);
    }

    //redirect each subcommand according to chunk position
    list_for_each_entry(scmd, &cmd->scmd_list, list) {
    	struct msb_range *range;
    	uint64_t start_lba_main;

    	start_lba_main = get_start_lba(scmd->lba);
    	range = msb_hashtable_get_range(ht, start_lba_main);

    	if(range != NULL){
    		pr_debug("For scmd=%p, scmd->lba=%llu, scmd->len=%d, scmd->vol=%s forund range=%p, start_lba_main=%llu, start_lba_aux=%llu\n",
    				scmd, scmd->lba, scmd->len, scmd->vol->name, range, range->start_lba_main, range->start_lba_aux);
    		res = __redirect_scmd(scmd, range, data);
    	} else if(read_caching_enabled){ //no range and caching enabled
    		pr_debug("For cmd=%p scmd=%p lba=%llu len=%d There is no range in HT. num_caching_cmd=%d of %d \n",
    				cmd, scmd, scmd->lba, scmd->len, atomic_read(&data->num_caching_cmd), MSB_MAX_CACHING_CMD);
    		// may be it is a good idea to add this checking here: if(atomic_read(&data->num_caching_cmd) < MSB_MAX_CACHING_CMD){...
    		if(atomic_read(&data->num_caching_cmd) < MSB_MAX_CACHING_CMD){
				range = msb_range_create(data, start_lba_main);

				if(!range){ //failed to create range
					pr_debug("Failed to create range, not redirecting scmd=%p.\n", scmd);
					goto out_unlock;
				}

				msb_hashtable_add_range(ht, range);
				pr_debug("for scmd=%p created range=%p start_lba_main=%llu, start_lba_aux=%llu\n",
						scmd, range, range->start_lba_main, range->start_lba_aux);

				__mark_scmd_for_caching(scmd, range);

				//insert after scmd marked for caching so that we dont start eviction of this range
				write_lock_bh(&data->tree_lock);
					msb_range_tree_insert(data, range);
				write_unlock_bh(&data->tree_lock);
    		}
    		else{
    			pr_debug("Too much caching cmd, hence don't cache this one scmd=%p lba=%llum len=%d\n",
    					scmd, scmd->lba, scmd->len);
    			continue; //just skip this subcommand, no redirection, no caching
    		}
    	} else { //range == NULL caching disabled
    		pr_debug("For cmd=%p scmd=%p lba=%llu len=%d There is no range in HT. Read caching disabled. Go to the next scmd \n",
    		    				cmd, scmd, scmd->lba, scmd->len);
    		continue;
    	}
    }
out_unlock:
	if(read_caching_enabled){ // correct unlock
    	msb_unlock_buckets(ht, cmd->lba, cmd->len, WRITE);
    } else {
    	msb_unlock_buckets(ht, cmd->lba, cmd->len, READ);
    }

    list_for_each_entry(scmd, &cmd->scmd_list, list){
    	pr_debug("OUT cmd=%p [%s] scmd=%p : (vol=%s, lba=%llu, len=%d)\n",
    			cmd, cmd->dir == WRITE ? "W" : "R", scmd, scmd->vol->name, scmd->lba, scmd->len);
    }

    return res;
}
