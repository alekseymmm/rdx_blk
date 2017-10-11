/*
 * rdx_blk_debug.h
 *
 *  Created on: 11 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_DEBUG_H_
#define RDX_BLK_DEBUG_H_

//void __print_range(struct msb_range *range);

void print_used_ranges(struct msb_data* data);

void print_all_ranges(struct msb_data* data);

#endif /* RDX_BLK_DEBUG_H_ */
