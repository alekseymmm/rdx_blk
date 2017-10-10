/*
 * rdx_blk_data.h
 *
 *  Created on: 10 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_DATA_H_
#define RDX_BLK_DATA_H_

struct msb_data *__alloc_data(struct rdx_blk *dev, uint64_t range_size_sectors, uint64_t max_num_evict_cmd);

void __free_data(struct msb_data *data);

#endif /* RDX_BLK_DATA_H_ */
