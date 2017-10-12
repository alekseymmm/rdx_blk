/*
 * rdx_blk_ranges.c
 *
 *  Created on: 9 окт. 2017 г.
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

#include "rdx_blk.h"
#include "rdx_blk_hashtable.h"
#include "rdx_blk_range.h"
#include "rdx_blk_request.h"


//must be called under data->used_ranges_lock
inline uint64_t __get_new_aux_dsc_lba(struct msb_data *data){
	uint64_t res = 0;

	res = find_next_zero_bit(data->used_ranges_bitmap, data->num_ranges, data->last_aux_range_bit);
	//TODO: Think! may be it should be + 1, because it is a case when we have
	//[1111000] last_bit = 3, then evict them all and get  [000<last_pos>000]
	//so we start new filling at the last eviction pos and reusing that range. is it ok?
	pr_debug("In used_ ranges after the bit=%llu next zerof bit=%llu \n",
			data->last_aux_range_bit, res);
	if(res == data->num_ranges){
		// no empty ranges till the end of bitmap
		//lets check if we have some free range since the beginning
		data->last_aux_range_bit = 0;
		res = find_next_zero_bit(data->used_ranges_bitmap, data->num_ranges, data->last_aux_range_bit);

		pr_debug("In used_ ranges after the bit=%llu next zerof bit=%llu \n",
					data->last_aux_range_bit, res);

		//still nothing found
		if(res == data->num_ranges){
			pr_debug("No empty ranges available, zero bit pos=%llu, num_ranges=%llu\n",
				res, data->num_ranges);
			return -ENOSPC;
		}
	}

	data->last_aux_range_bit = res;
	set_bit(res, data->used_ranges_bitmap); //mark it as used
	pr_debug("In used_ ranges set bit=%llu for start_lba_aux=%llu\n", res, res * data->range_size_sectors);
	res = res * data->range_size_sectors; //convert it to lba

	return res;
}

//must be called under data->used_ranges_lock
inline void __put_aux_dsc_lba(struct msb_data *data, uint64_t range_start_lba_aux){
	uint32_t bit_pos;

	bit_pos = range_start_lba_aux / data->range_size_sectors;
	pr_debug("for range with start_lba_aux=%llu clear bit %d in used_ranges\n",
			range_start_lba_aux, bit_pos);
	clear_bit(bit_pos, data->used_ranges_bitmap); //mark it as clear
}

/**
 * Allocates a new range.
 * @param data - the main volume context.
 * @return pointer to the new entry, or NULL if failed.
 */
struct msb_range *msb_range_create(struct msb_data *data, uint64_t start_lba_main){
    struct msb_range *range = NULL;
	int64_t res = 0;

	write_lock_bh(&data->used_ranges_lock);
		res = __get_new_aux_dsc_lba(data);
	write_unlock_bh(&data->used_ranges_lock);

		//if there are no empty ranges in aux
		if( res == -ENOSPC){
			set_bit(MSB_FLAG_FULL, &data->flags);
			pr_debug("No empty ranges in aux. Range cannot be created.\n");
			return NULL;
		} else{
			range = kmem_cache_zalloc(range_cachep, GFP_ATOMIC);

			if(!range){
				pr_debug("kmem cache range allocation failed!\n");
				return NULL;
			}
			range->bitmap = kzalloc(BITS_TO_LONGS(data->range_bitmap_size) * sizeof(unsigned long), GFP_ATOMIC);
			if(!range->bitmap){
				pr_debug("Cannot allocate bitmap for range=%p for start_lba_main=%llu\n", range, start_lba_main);
				kmem_cache_free(range_cachep, range);
				return NULL;
			}
			range->data = data;
			range->start_lba_main = start_lba_main;
			range->start_lba_aux = res;
			atomic_set(&range->ref_cnt, 1);
//			range->scpriv.vf = data->vf;
//			range->scpriv.next = NULL;

			INIT_HLIST_NODE(&range->ht_node);
			rwlock_init(&range->lock);

			pr_debug("new range=%p allocated, start_lba_main=%llu, start_lba_aux=%llu \n",
					range, range->start_lba_main, range->start_lba_aux);
		}

    return range;
}

/**
 * Deallocate range. and remove from ht and rb_tree
 * @param @range - the range.
 * @return Nothing.
 */
void msb_range_delete(struct msb_range *range){

	pr_debug("For range=%p  start_lba_main=%llu start_lba_aux=%llu lock buckets in HT before range deletion\n",
			range, range->start_lba_main, range->start_lba_aux);
	msb_lock_buckets(range->data->ht, range->start_lba_main, 0, WRITE);

	pr_debug("for range=%p lock tree_lock before range deletion\n", range);
	write_lock_bh(&range->data->tree_lock);

	pr_debug("for range=%p lock data->used_ranges before range deletion\n", range);
	write_lock_bh(&range->data->used_ranges_lock);

	msb_hashtable_del_range(range->data->ht, range);
	msb_range_erase_from_tree(range->data, range);
	__put_aux_dsc_lba(range->data, range->start_lba_aux);

	pr_debug("for range=%p unlock data->used_ranges after range deletion\n", range);
	write_unlock_bh(&range->data->used_ranges_lock);

	pr_debug("for range=%p unlock tree_lock after range deletion\n", range);
	write_unlock_bh(&range->data->tree_lock);

	pr_debug("For range=%p  start_lba_main=%llu start_lba_aux=%llu unlock buckets in HT after range deletion\n",
			range, range->start_lba_main, range->start_lba_aux);
    msb_unlock_buckets(range->data->ht, range->start_lba_main, range->data->range_size_sectors, WRITE);

	pr_debug("Range %p start_lba_main=%llu deleted\n",
    		range, range->start_lba_main);
	kfree(range->bitmap);
    kmem_cache_free(range_cachep, range);
}

//must be called under tree_lock
void msb_delete_all_ranges(struct msb_data *data){
	struct msb_hashtable *ht;
	struct rb_node *tree_node;
	struct rb_root *tree_root;

	ht = data->ht;
	tree_root = &data->ranges;

	for(tree_node = rb_first(tree_root); tree_node; tree_node = rb_next(tree_node)){
		struct msb_range *range;
		range = container_of(tree_node, struct msb_range, tree_node);

		msb_range_delete(range);
	}
}

//must be called under tree_lock
int msb_range_tree_insert(struct msb_data *data, struct msb_range *range){
	struct rb_root  *tree_root = &data->ranges;
	struct rb_node **new = &(tree_root->rb_node);
	struct rb_node *parent = NULL;

	/* Figure out where to put new node */
	while(*new){
		struct msb_range *this  = container_of(*new, struct msb_range, tree_node);

		parent = *new;
		if(range->start_lba_main <  this->start_lba_main){
			new = &((*new)->rb_left);
		}
		else if(range->start_lba_main > this->start_lba_main){
			new = &((*new)->rb_right);
		}
		else {
			pr_debug("Failed insertion to tree range=%p start_lba_main=%llu  (Key already exist!)\n",
						range, range->start_lba_main);
			return false;
		}
	}

	rb_link_node(&range->tree_node, parent, new);
	rb_insert_color(&range->tree_node, tree_root);
	pr_debug("Range=%p start_lba_main=%llu inserted into range tree\n",
			range, range->start_lba_main);
	return true;
}

//must be called under tree_lock
void msb_range_erase_from_tree(struct msb_data *data, struct msb_range *range){
	struct rb_root *tree_root = &data->ranges;

	rb_erase(&range->tree_node, tree_root);
	pr_debug("Erased from tree range=%p, start_lba_main=%llu\n",
			range, range->start_lba_main);
}

//must be called under range lock
void msb_setbits_in_range(struct msb_range *range, uint64_t lba, uint32_t len){
	uint64_t offset = lba - range->start_lba_main;

	int offset_in_bits = offset / MSB_BLOCK_SIZE_SECTORS;
	int len_in_bits = len / MSB_BLOCK_SIZE_SECTORS;

	pr_debug("Set bits in mask for range=%p, offset_bit=%d, len_bits=%d\n",
			range, offset_in_bits, len_in_bits);
	bitmap_set(range->bitmap, offset_in_bits, len_in_bits);
}

//must be called under range lock
void msb_clearbits_in_range(struct msb_range *range, uint64_t lba, uint32_t len){
	uint64_t offset = lba - range->start_lba_main;

	int offset_in_bits = offset / MSB_BLOCK_SIZE_SECTORS;
	int len_in_bits = len / MSB_BLOCK_SIZE_SECTORS;

	pr_debug("Clear bits in mask for range=%p, offset_bit=%d, len_bits=%d\n",
			range, offset_in_bits, len_in_bits);
	bitmap_clear(range->bitmap, offset_in_bits, len_in_bits);
}

//must be called under range->lock
int msb_intersect_range(struct msb_data *data, struct msb_range *range, struct rdx_request *req){
	int first_bit, next_zero_bit;
	uint64_t offset;
	uint64_t intersection;
	struct bio *split;
	unsigned int msb_bitmap_size = data->range_bitmap_size;
	struct bio_set *split_bioset = data->dev->split_bioset;
	bool intersect_happened = false;

	struct bio *usr_bio = req->usr_bio;

	int bio_end_sect_bit = lba2bit(range, bio_end_sector(usr_bio)) - 1; //the last bit covered by bio

	while(1){ //is it a good idea ? It is!
		int bio_first_sect_bit = lba2bit(range, bio_first_sector(usr_bio));

		pr_debug("Intersect bio=%p first_sect=%lu, len=%d with range=%p start_lba_main=%llu\n",
				usr_bio, bio_first_sector(usr_bio), bio_sectors(usr_bio), range, range->start_lba_main);

		first_bit = find_next_bit(range->bitmap, msb_bitmap_size, bio_first_sect_bit);
		next_zero_bit = find_next_zero_bit(range->bitmap, msb_bitmap_size, first_bit);

		if(next_zero_bit != data->range_bitmap_size){
			next_zero_bit--; //if we  are still not in the end of the mask
		}

		pr_debug("bio_first_sect_bit=%d, bio_end_sect_bit=%d, in range first_bit=%d, last_bit=%d\n",
				bio_first_sect_bit, bio_end_sect_bit, first_bit, next_zero_bit);

		/* Break point  - there are no more intersections
		 * scmd       |------|
		 * range               |------
		 */
		if(first_bit > bio_end_sect_bit){
			//this means that the last subcommand in the list is not intersected with any bits in range
			//hence it is command to main and could be cached (TODO: consider read caching for bio)
			usr_bio->bi_bdev = data->dev->main_bdev;
			pr_debug("First found set bit =%d  > bio_end_sect_bit=%d, no more intersection.\n",
					first_bit, bio_end_sect_bit);
//			if((atomic_read(&data->num_caching_cmd) < MSB_MAX_CACHING_CMD) && read_caching_enabled){
//				__mark_scmd_for_caching(scmd, range);
//			}
			break;
		}

		intersect_happened = true;
		/* First case of intersection
		 * bio        |----------
		 * range           |---------
		 * new bio    |----| (to main) - will be cached because range is set in priv
		 */
		if(first_bit > bio_first_sect_bit){

			pr_debug("First case of intersection bio and range. Send split bio to main.\n");

			intersection  = (first_bit - bio_first_sect_bit) * MSB_BLOCK_SIZE_SECTORS;
			split = bio_split(usr_bio, intersection, GFP_NOIO, split_bioset);
			if(!split){
				pr_debug("Cannot split\n");
				req->err = -ENOMEM;
				__req_put(req);
			}
			else{
				bio_chain(split, usr_bio);
				split->bi_bdev = data->dev->main_bdev;

				pr_debug("split_bio(%p), bdev=%s, first_sector=%lu, size=%d\n",
						split, split->bi_bdev->bd_disk->disk_name, bio_first_sector(split), bio_sectors(split));
				submit_bio(split);
			}

//			if((atomic_read(&data->num_caching_cmd) < MSB_MAX_CACHING_CMD) && read_caching_enabled){
//				__mark_scmd_for_caching(new_scmd, range);
//			}
			continue;
		}

		/* Second case of intersection
		 * bio        |-------
		 * range  |--------------
		 */
		if(first_bit <= bio_first_sect_bit){

			pr_debug("Second case of intersection. Redirect current bio.\n");
			offset = bio_first_sector(usr_bio) - range->start_lba_main;

			if(bio_end_sect_bit > next_zero_bit){
				/*
				 * bio            |--------|
				 * range     |-------|
				 * new bio        |--| (to aux)
				 */

				pr_debug("Not full bio covered by range. Insert new split bio . Continue redirecting....\n");

				intersection = bit2lba(range, next_zero_bit + 1) - bio_first_sector(usr_bio);
				split = bio_split(usr_bio, intersection, GFP_NOIO, split_bioset);
				if(!split){
					pr_debug("Cannot split\n");
					req->err = -ENOMEM;
					__req_put(req);
				}
				else{
					split->bi_bdev = data->dev->aux_bdev;
					split->bi_iter.bi_sector = range->start_lba_aux + offset;

					bio_chain(split, usr_bio);
					pr_debug("To range %p add new split bio %p, bdev=%s, first_sector=%lu, size=%d\n",
							range, split, split->bi_bdev->bd_disk->disk_name, bio_first_sector(split), bio_sectors(split));
					submit_bio(split);
				}
//				new_scmd->priv = &range->scpriv; //
//				atomic_inc(&range->ref_cnt);
//			    pr_debug("For range=%p ref_cnt =%d\n",
//			    		range, atomic_read(&range->ref_cnt));
				continue;
			}

			else {//bio_end_sect_bit <= last_bit
				pr_debug("Full bio=%p covered by range=%p. Redirect bio, and break.\n", usr_bio, range);

				usr_bio->bi_iter.bi_sector = range->start_lba_aux + offset;
				usr_bio->bi_bdev = data->dev->aux_bdev;

//				scmd->priv = &range->scpriv; //
//				atomic_inc(&range->ref_cnt);
//			    pr_debug("For range=%p ref_cnt =%d\n",
//			    		range, atomic_read(&range->ref_cnt));
				break;
			}
		}
	}

	//all splitted parts are submitted  then submit usr bio itself
	if(intersect_happened){
		req->range = range;
		atomic_inc(&range->ref_cnt);
		pr_debug("Intersection happend , for range=%p ref_cnt=%d\n",
				range, atomic_read(&range->ref_cnt));
	}
	submit_bio(usr_bio);


	return 0;
}
