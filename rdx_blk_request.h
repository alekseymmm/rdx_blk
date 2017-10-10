/*
 * rdx_blk_request.h
 *
 *  Created on: 3 окт. 2017 г.
 *      Author: alekseym
 */

#ifndef RDX_BLK_REQUEST_H_
#define RDX_BLK_REQUEST_H_

#include "rdx_blk.h"

blk_qc_t rdx_blk_make_request(struct request_queue *q, struct bio *bio);

void __req_put(struct rdx_request *req);

struct rdx_request *__create_req(struct bio *bio, struct rdx_blk *dev);

#endif /* RDX_BLK_REQUEST_H_ */
