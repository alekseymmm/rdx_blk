/*
 * rdx_blk_hashtable.c
 *
 *  Created on: 9 окт. 2017 г.
 *      Author: alekseym
 */

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>

#include "rdx_blk.h"
#include "rdx_blk_hashtable.h"

//it is important that for sequential keys hash function returns sequential hashes
inline uint64_t msb_hash(struct msb_hashtable *ht, uint64_t key){
	return (key / ht->data->range_size_sectors) & ht->hashmask;
}

/**
 * Allocate and initialize a hashtable.
 * @param data - the private msb plugin data pointer
 * @return a hashtable pointer, or NULL for error.
 */
struct msb_hashtable *msb_hashtable_create(struct msb_data *data)
{
    struct msb_hashtable *ht;
    size_t i;

    /* Alloc memory for hashtable structure */
    ht = kzalloc(sizeof(struct msb_hashtable), GFP_KERNEL);
    if (!ht) {
        pr_debug("Could not allocate memory for the hash table.\n");
        return NULL;
    }

    /* Initializing structure */
    ht->data = data;
    ht->buckets_num = 1 << MSB_HT_BUCKET_SHIFT;

    ht->hashmask = ((uint64_t)1 << MSB_HT_BUCKET_SHIFT) - 1;

    /* Log hashtable parameters */
    pr_debug("\nMSB ht buckets_num: %zu; hashmask: %llx\n", ht->buckets_num,
               ht->hashmask);

    /* Allocating buckets */
    ht->buckets = vzalloc(ht->buckets_num * sizeof(struct msb_bucket));
    if (!ht->buckets) {
        pr_debug("Could not allocate memory for the hash buckets.\n");
        goto error;
    }

    /* Initialize buckets */
    for (i = 0; i < ht->buckets_num; i++){
        INIT_HLIST_HEAD(&ht->buckets[i].head);
        rwlock_init(&ht->buckets[i].lock);
    }

    rwlock_init(&ht->lock);
    return ht;

error:
    kfree(ht);
    return NULL;
}

/**
 * Delete a hashtable.
 * @param ht - the hashtable.
 * @return Nothing.
 */
void msb_hashtable_delete(struct msb_hashtable *ht)
{
    if (!ht)
        return;
    vfree(ht->buckets);
    kfree(ht);
}

void msb_lock_buckets(struct msb_hashtable *ht, uint64_t lba, uint32_t len, int lock_type){
	uint64_t start_lba_main = 0;
	uint64_t hash = 0;
	struct msb_data *data = ht->data;

	uint32_t slen; /* command length fitting in a range */
	uint64_t offset; /*offset in current range*/
	uint64_t end_lba = lba + len; //when to stop

	do{

		offset = lba % data->range_size_sectors;
		slen = data->range_size_sectors - offset;

		start_lba_main = get_start_lba(lba, data);
		hash = msb_hash(ht, start_lba_main);

		pr_debug("For lba=%llu len=%d slen=%d (start_lba_main=%llu) offset%llu: lock bucket number=%llu\n",
				lba, len, slen, start_lba_main, offset, hash);
		if(lock_type == WRITE){
			write_lock(&ht->buckets[hash].lock);
		} else {// read lock
			read_lock(&ht->buckets[hash].lock);
		}

		lba += slen;
	}while(lba < end_lba);
}


void msb_unlock_buckets(struct msb_hashtable *ht, uint64_t lba, uint32_t len, int unlock_type){
	uint64_t start_lba_main = 0;
	uint64_t hash = 0;
	struct msb_data *data = ht->data;

	uint32_t slen; /* command length fitting in a range */
	uint64_t offset; /*offset in current range*/
	uint64_t end_lba = lba + len; //when to stop

	do{
		offset = lba % data->range_size_sectors;
		slen = data->range_size_sectors - offset;

		start_lba_main = get_start_lba(lba, data);
		hash = msb_hash(ht, start_lba_main);

		pr_debug("For lba=%llu len=%d slen=%d (start_lba_main=%llu) offset%llu: unlock bucket number=%llu\n",
				lba, len, slen, start_lba_main, offset, hash);
		if(unlock_type == WRITE){
			write_unlock(&ht->buckets[hash].lock);
		} else { // read lock
			read_unlock(&ht->buckets[hash].lock);
		}

		lba += slen;
	}while(lba < end_lba);
}

/**
 * hashtable_add_range - Adds a new item to a hashtable.
 * Must be called under the lock of corresponding bucket.
 * @param ht - the hashtable;
 * @param range - pointer to msb_range to store in the hashtable.
 * @return 0 for success, or error code.
 */
int msb_hashtable_add_range(struct msb_hashtable  *ht, struct msb_range *range)
{
    uint64_t hashed_key;
    struct msb_bucket *bucket;

    if (unlikely(!ht)) {
        pr_debug("Hashtable is (NULL).\n");
        return -EINVAL;
    }

    if (unlikely(!range)) {
        pr_debug("Entry is (NULL).\n");
        return -EINVAL;
    }

    hashed_key = msb_hash(ht, range->start_lba_main);
    pr_debug("For range=%p range->start_lba_main=%llu : hashed_key=%llu\n",
    		range, range->start_lba_main, hashed_key);

    bucket = &ht->buckets[hashed_key];

    hlist_add_head(&range->ht_node, &bucket->head);

    pr_debug("range %p  range->start_lba_main=%llu added to HT\n",
    		range, range->start_lba_main);

    return 0;
}

/**
 * hashtable_del_range - Delete range from hashtable.
 * Must be called under the lock of corresponding bucket.
 * @param ht - the hashtable;
 * @param range - pointer to msb_range to store in the hashtable.
 * @return 0 for success, or error code.
 */
int msb_hashtable_del_range(struct msb_hashtable* ht, struct msb_range* range) {
	uint64_t hashed_key;
	struct msb_bucket* bucket;

	if (unlikely(!ht)) {
		pr_debug("Hashtable is (NULL).\n");
		return -EINVAL;
	}
	if (unlikely(!range)) {
		pr_debug("Entry is (NULL).\n");
		return -EINVAL;
	}
	hashed_key = msb_hash(ht, range->start_lba_main);
	pr_debug("For range=%p range->start_lba_main=%llu : hashed_key=%llu\n",
			range, range->start_lba_main, hashed_key);
	bucket = &ht->buckets[hashed_key];
	hlist_del(&range->ht_node);
	pr_debug("range %p  range->start_lba_main=%llu deleted from HT\n", range,
			range->start_lba_main);
	return 0;
}

struct msb_range *msb_hashtable_get_range(struct msb_hashtable *ht, uint64_t key){
	uint64_t hashed_key;
	struct msb_bucket* bucket = NULL;
	struct msb_range *res = NULL;
	struct msb_range *cur_range = NULL;

	if (unlikely(!ht)) {
		pr_debug("Hashtable is (NULL).\n");
		return NULL;
	}

	hashed_key = msb_hash(ht, key);
	bucket = &ht->buckets[hashed_key];

	hlist_for_each_entry(cur_range, &bucket->head, ht_node){
		if(cur_range->start_lba_main == key){
			res = cur_range;
			pr_debug("range=%p for key=%llu is found in bucket[%llu]\n",
					res, key, hashed_key);
			return res;
		}
	}

	pr_debug("For key=%llu there is no range in HT\n", key);

	return res;
}
