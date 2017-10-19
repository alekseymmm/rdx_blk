/*
 * rdx_blk_debug.c
 *
 *  Created on: 11 окт. 2017 г.
 *      Author: alekseym
 */

#include <linux/bitmap.h>

#include "rdx_blk.h"

//must be called under range->lock
void __print_range(struct msb_range *range, char *buf){

	bitmap_print_to_pagebuf(true, buf, range->bitmap, range->data->range_bitmap_size);

	pr_debug("range=%p start_lba_main=%llu, start_lba_aux=%llu, ref_cnt=%d set bits in bitmap: %s",
			range, range->start_lba_main, range->start_lba_aux, atomic_read(&range->ref_cnt), buf);
}

void print_all_ranges(struct msb_data* data){
	struct msb_hashtable *ht;
	struct rb_node *tree_node;
	struct rb_root *tree_root;
	char  *buf; // for printing bitmap

	ht = data->ht;
	tree_root = &data->ranges;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(buf){
		read_lock(&data->tree_lock);
		for(tree_node = rb_first(tree_root); tree_node; tree_node = rb_next(tree_node)){
			struct msb_range *range;
			range = container_of(tree_node, struct msb_range, tree_node);
			read_lock(&range->lock);
				__print_range(range, buf);
			read_unlock(&range->lock);
		}
		read_unlock(&data->tree_lock);
		kfree(buf);
	} else{
		pr_debug("Cannot allocate page buf for printing\n");
	}

	pr_debug("Ranges printing done!\n");
}


void print_used_ranges(struct msb_data* data){
	char  *buf; // for printing bitmap

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(buf){
		read_lock(&data->used_ranges_lock);
		bitmap_print_to_pagebuf(true, buf, data->used_ranges_bitmap,data->num_ranges);
		pr_debug("num_ranges=%llu, set bits in bitmap: %s \n",
				data->num_ranges, buf);
		read_unlock(&data->used_ranges_lock);
		kfree(buf);
	} else{
		pr_debug("Cannot allocate page buf for printing\n");
	}
	pr_debug("Ranges printing done!\n");
}




