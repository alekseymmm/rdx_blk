/*
 * rdx_blk_service.c
 *
 *  Created on: 12 окт. 2017 г.
 *      Author: alekseym
 */

#include "rdx_blk.h"
#include "rdx_blk_request.h"

int generate_bio_test(struct rdx_blk *dev){
	struct bio *bio;
	struct rdx_request *req;
	uint64_t pages, offset, bytes, xferred, len;
	size_t i;
	char *data_addr;

	bytes = 8192;
	pages = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;

	bio = bio_alloc(GFP_NOIO, pages);
	if (!bio) {
		pr_debug("Cannot allocate bio\n");
		return -ENOMEM;
	}
	bio->bi_iter.bi_sector = 0;
	bio->bi_bdev = dev->main_bdev;
	bio->bi_opf = REQ_OP_READ;

	req = __create_req(bio, dev, RDX_REQ_EVICT_R);
	if(!req){
		pr_debug("for bio=%p cannot allocate req\n", bio);
		return -ENOMEM;
	}

	req->buf = kmalloc(bytes, GFP_KERNEL);

	if(!req->buf){
		pr_debug("Cannot allocate buf for req=%p\n", req);
		kmem_cache_free(rdx_request_cachep, req);
		bio_put(bio);
		return -ENOMEM;
	}

	offset = (uint64_t)((long)req->buf % PAGE_SIZE);

	bio->bi_private = req;

	data_addr = req->buf;
	xferred = 0;
	for (i = 0; i < pages; i++) {
		if (offset + bytes - xferred < PAGE_SIZE)
			len = bytes - xferred;
		else
			len = PAGE_SIZE - offset;

		bio_add_page(bio, virt_to_page(data_addr), len, offset);
		offset = 0;
		data_addr += len;
		xferred += len;
	}

	pr_debug("Generate bio=%p, req=%p, dev=%s, first_sect=%lu, sectors=%d\n",
			bio, req, bio->bi_bdev->bd_disk->disk_name, bio_first_sector(bio), bio_sectors(bio));
	submit_bio(bio);
	return 0;
}
