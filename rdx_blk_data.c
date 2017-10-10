/*
 * rdx_blk_data.c
 *
 *  Created on: 9 окт. 2017 г.
 *      Author: alekseym
 */

#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/slab.h>

#include "rdx_blk.h"
#include "rdx_blk_hashtable.h"
#include "rdx_blk_range.h"


struct msb_data *__alloc_data(struct rdx_blk *dev, uint64_t range_size_sectors, uint64_t max_num_evict_cmd)
{
    struct msb_data *data = NULL;
    uint64_t bitmap_size_bytes = 0;
    char *test_ptr = NULL;

    /* Allocate and initialize a new data */
    data = kmalloc(sizeof(*data), GFP_ATOMIC);
    if(!data){
    	pr_debug("Cannot allocate msb_data\n");
    	goto out_free;
    }
    data->dev = dev;
    data->range_size_sectors = range_size_sectors;
    data->range_bitmap_size = (range_size_sectors / MSB_BLOCK_SIZE_SECTORS);

    pr_debug("Range size in 512b sectors=%llu, range bitmap size=%llu\n",
    		data->range_size_sectors, data->range_bitmap_size);

    //this is test for bitmap allocation using kmalloc
	bitmap_size_bytes = BITS_TO_LONGS(data->range_bitmap_size) * sizeof(unsigned long);

    pr_debug("Max number of evict cmd = %llu\n", max_num_evict_cmd);
    data->max_num_evict_cmd = max_num_evict_cmd;

	test_ptr = kzalloc(bitmap_size_bytes, GFP_ATOMIC);
	if(!test_ptr){
		pr_debug("Range %llu is too big for kmalloc allocation of bitmap of size=%llu in msb\n",
				data->range_size_sectors, bitmap_size_bytes);
		return NULL;
	}
	kfree(test_ptr);

    atomic_set(&data->num_evict_cmd, 0);
    atomic_set(&data->num_caching_cmd, 0);
    rwlock_init(&data->tree_lock);
    init_waitqueue_head(&data->wq_evict_cmd);
    data->last_aux_range_bit = 0;

    data->ht = msb_hashtable_create(data);
    if (!data->ht) {
        pr_debug("Could not create data->ht\n");
        goto out_free;
    }
    data->ranges = RB_ROOT;
    data->flags = 0;

    rwlock_init(&data->used_ranges_lock);

    data->num_ranges = get_capacity(data->dev->main_bdev->bd_disk) / data->range_size_sectors - 1; // TODO: think about this
    //using kzalloc is better for performance but limited in size
    data->used_ranges_bitmap = vzalloc(sizeof(long) * BITS_TO_LONGS(data->num_ranges));

    if(!data->used_ranges_bitmap){
    	pr_debug("Could not allocate bitmap of used ranges\n");
    	goto out_free;
    }
    pr_debug("Num ranges=%llu, size of used_ranges_bitmap = %llu bytes\n",
    		data->num_ranges, sizeof(long) * BITS_TO_LONGS(data->num_ranges));

out_free:
    kfree(data);
    data = NULL;

    return data;
}


void __free_data(struct msb_data *data){
	msb_delete_all_ranges(data);

	msb_hashtable_delete(data->ht);
	vfree(data->used_ranges_bitmap);
	kfree(data);
}
