/*
 * rdx_blk_service.h
 *
 *  Created on: 12 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_SERVICE_H_
#define RDX_BLK_SERVICE_H_

void __evict_timer_handler(unsigned long data_ptr);

void start_evict_service(struct rdx_blk *dev);
int stop_evict_service(struct rdx_blk *dev);

#endif /* RDX_BLK_SERVICE_H_ */
