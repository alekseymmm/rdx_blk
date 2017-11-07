/*
 * rdx_blk.h
 *
 *  Created on: 3 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_H_
#define RDX_BLK_H_

#include <linux/module.h>

#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/bitmap.h>
#include <linux/types.h>

#define KERNEL_SECT_SIZE_SHIFT 9
#define KERNEL_SECT_SIZE (1 << KERNEL_SECT_SIZE_SHIFT)
#define RDX_BLK_MIN_POOL_PAGES 128
#define MSB_DEFAULT_RANGE_SIZE_SECTORS (20 * 1024 * 2)
#define MSB_DEFAULT_MAX_NUM_EVICT_CMD (8)
#define MSB_BLOCK_SIZE_SECTORS (8)

#define MSB_HT_BUCKET_SHIFT  (27)

extern struct rdx_blk *rdx_blk;
extern struct kmem_cache *rdx_request_cachep;
extern struct msb_data *rdx_msb_data;

extern struct kmem_cache *range_cachep;

/** MSB workqueue */
extern struct workqueue_struct *rdx_blk_wq;

extern bool  read_caching_enabled;

enum rdx_req_type {
	RDX_REQ_RW					= 0,
	RDX_REQ_EVICT_R				= 1,
	RDX_REQ_EVICT_W				= 2,
};

struct rdx_request{
	struct rdx_blk		*dev;
	struct bio 			*usr_bio;
	atomic_t 			ref_cnt;
	unsigned int		rw;
	sector_t 			first_sector;
	sector_t 			sectors;
	int 				err;
	bio_end_io_t		*__usr_bio_end_io;
	void 				*usr_bio_private;
	struct msb_range	*range;
	enum rdx_req_type 	type;
	char  				*buf;
	struct list_head	list;
	struct work_struct	work;
};

struct rdx_blk {
	struct request_queue 	*queue;
	struct gendisk 			*gd;
	struct block_device 	*main_bdev;
	struct block_device 	*aux_bdev;
	char 					*name;
	sector_t 				sectors;
	struct bio_set 			*split_bioset;
	struct msb_data 		*data;
	struct timer_list		evict_timer;

	struct list_head		req_list;
	struct work_struct		penging_req_work;
	atomic_t 				processing_pending_req;
	spinlock_t				req_list_lock;
};

struct msb_data {
	uint64_t 					range_size_sectors;
	uint64_t					max_num_evict_cmd;
	uint64_t					range_bitmap_size;
	struct rdx_blk 				*dev; 			 /** rdx_blk parent device */
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

struct msb_range{
	uint64_t 			start_lba_main;
	uint64_t			start_lba_aux;

	//static bitmap is better and faster!
	//DECLARE_BITMAP(bitmap, MSB_BITMAP_SIZE);
	unsigned long		*bitmap;

	rwlock_t			lock;
	struct rb_node		tree_node;
	struct hlist_node	ht_node;
	struct msb_data 	*data;
	atomic_t 			ref_cnt;
};

/**
 * A hashtable bucket.
 * The ranges in the bucket are ordered by the key (LBA on the start_lba_main.)
 */
struct msb_bucket {
    struct hlist_head        head;              /**< The head of a hlist of entries */
    rwlock_t 				 lock;				/**< lock bucket */
};

/**
 * A hashtable for msb entries. The LBA on the start main value is used as the key.
 */
struct msb_hashtable {
    size_t                  buckets_num;        /**< Number of buckets in the table */
    struct msb_bucket       *buckets;           /**< The array of buckets */
    rwlock_t                lock;               /**< The table lock */
    uint64_t                hashmask;           /**< The hash mask */
    struct msb_data         *data;              /**< The private msb plugin data pointer */
};

enum rp_msb_data_flags {
    MSB_FLAG_FULL				= 0,        /**< This flag is set when  */
    MSB_FLAG_RESTORING			= 1,        /**< This flag is set when  */
    MSB_FLAG_DELETING    		= 2,
	MSB_EVICTION_IN_PROGRESS	= 3,        /** Set when data eviction in progress*/
	MSB_CANCEL_EVICTION			= 4,
};

enum rp_msb_range_flags {
	MSB_RANGE_EVICTING			= 0,
};



#define bio_first_sector(bio) ((bio_end_sector(bio) - bio_sectors(bio)))

static inline uint64_t get_start_lba(uint64_t x, struct msb_data *data){
	return (x - (x % data->range_size_sectors));
}

#endif /* RDX_BLK_H_ */
