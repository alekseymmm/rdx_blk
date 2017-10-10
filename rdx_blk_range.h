/*
 * rdx_blk_range.h
 *
 *  Created on: 9 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_RANGE_H_
#define RDX_BLK_RANGE_H_

/**
 * Allocates a new range.
 * @param data - the main volume context.
 * @return pointer to the new entry, or NULL if failed.
 */
struct msb_range *msb_range_create(struct msb_data *data, uint64_t start_lba_main);

/**
 * Deallocate range.
 * @param @range - the range.
 * @return Nothing.
 */
void msb_range_delete(struct msb_range *range);

void msb_delete_all_ranges(struct msb_data *data);

int msb_range_tree_insert(struct msb_data *data, struct msb_range *range);

void msb_range_erase_from_tree(struct msb_data *data, struct msb_range *range);

void msb_setbits_in_range(struct msb_range *range, uint64_t lba, uint32_t len);

void msb_clearbits_in_range(struct msb_range *range, uint64_t lba, uint32_t len);

int msb_intersect_range(struct msb_data *data, struct msb_range *range, struct rdx_request *req);

//returns lba corresponding to bit in range
static inline uint64_t bit2lba(struct msb_range *range, int bit_pos){
	return range->start_lba_main + bit_pos * MSB_BLOCK_SIZE_SECTORS;
}

static inline int lba2bit(struct msb_range *range, uint64_t lba){
	uint64_t offset = lba - range->start_lba_main;
	return offset / MSB_BLOCK_SIZE_SECTORS;
}

#endif /* RDX_BLK_RANGE_H_ */
