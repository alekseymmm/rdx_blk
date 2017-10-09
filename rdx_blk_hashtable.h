/*
 * rdx_blk_hashtable.h
 *
 *  Created on: 9 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_HASHTABLE_H_
#define RDX_BLK_HASHTABLE_H_

 /**
 * Allocate and initialize a hashtable.
 * @param data - the private rrc plugin data pointer for the main volume.
 * @return a hashtable pointer, or NULL for error.
 */
struct msb_hashtable *msb_hashtable_create(struct msb_data *data);

/**
 * Delete a hashtable.
 * @param ht - the hashtable.
 * @return Nothing.
 */
void msb_hashtable_delete(struct msb_hashtable *ht);

void msb_lock_buckets(struct msb_hashtable *ht, uint64_t lba, uint32_t len, int lock_type);

void msb_unlock_buckets(struct msb_hashtable *ht, uint64_t lba, uint32_t len, int unlock_type);

int msb_hashtable_add_range(struct msb_hashtable  *ht, struct msb_range *range);

int msb_hashtable_del_range(struct msb_hashtable* ht, struct msb_range* range);

struct msb_range *msb_hashtable_get_range(struct msb_hashtable *ht, uint64_t key);


#endif /* RDX_BLK_HASHTABLE_H_ */
