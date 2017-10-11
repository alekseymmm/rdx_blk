/*
 * rdx_blk_filter.h
 *
 *  Created on: 10 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_FILTER_H_
#define RDX_BLK_FILTER_H_

int msb_write_filter(struct msb_data *data, struct bio *bio);

int msb_read_filter(struct msb_data *data, struct bio *bio);

#endif /* RDX_BLK_FILTER_H_ */
