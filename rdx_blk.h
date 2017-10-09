/*
 * rdx_blk.h
 *
 *  Created on: 3 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_H_
#define RDX_BLK_H_

#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/bitmap.h>
#include <linux/types.h>

#define RDX_BLK_MIN_POOL_PAGES 128

struct rdx_request{
	struct rdx_blk 	*dev;
	struct bio 		*usr_bio;
	atomic_t 		ref_cnt;
	unsigned int	rw;
	sector_t 		first_sector;
	sector_t 		sectors;
	int 			err;
	bio_end_io_t	*__usr_bio_end_io;
	void 			*usr_bio_private;
};

struct rdx_blk {
	struct request_queue 	*queue;
	struct gendisk 			*gd;
	struct block_device 	*main_bdev;
	struct block_device 	*aux_bdev;
	char 					*name;
	sector_t 				sectors;
	struct bio_set 			*split_bioset;
};

struct msb_data {
    uint32_t magic;                              /**< Magic value */
    struct rvm_volume_filter    *vf;             /**< Volume filter */
    struct rvm_volume_service   *vs;             /**< Volume service */
    struct rvm_volume           *main_vol;       /**< Main volume */
    struct rvm_volume           *aux_vol;        /**< Main volume */

    atomic_t                    ref_cnt;         /**< Reference counter */
    struct list_head            list;            /**< Entry of struct tier_data list */

    rwlock_t                	tree_lock;       /**< Ranges tree lock */
    struct msb_hashtable		*ht;			 /**< Hashtable of ranges */
    struct rb_root				ranges;			 /**< RB tree to store ranges */
    uint64_t 					num_ranges;		 /**< Total number of ranges in aux */
    unsigned long 				flags;			 /**< Data status flags */

    rwlock_t 					used_ranges_lock;
    long						*used_ranges_bitmap; /**< 0 means range is free*/

    struct work_struct			work;			 /**< Work for async data evict */
    atomic_t 					num_evict_cmd;
    wait_queue_head_t 			wq_evict_cmd;

    uint64_t 					last_aux_range_bit;

    atomic_t 					num_caching_cmd;
};

extern struct rdx_blk *rdx_blk;
extern struct kmem_cache *rdx_request_cachep;
extern struct msb_data *rdx_msb_data;

#define bio_first_sector(bio) (bio_end_sector(bio) - bio_sectors(bio))

#endif /* RDX_BLK_H_ */
