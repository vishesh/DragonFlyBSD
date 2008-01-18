/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/vfs/hammer/hammer_recover.c,v 1.4 2008/01/18 07:02:41 dillon Exp $
 */

#include "hammer.h"

static void hammer_recover_buffer_stage1(hammer_cluster_t cluster,
				int32_t buf_no);
static void hammer_recover_buffer_stage2(hammer_cluster_t cluster,
				int32_t buf_no);
static int  hammer_recover_record(hammer_cluster_t cluster,
				hammer_buffer_t buffer, int32_t rec_offset,
				hammer_record_ondisk_t rec);
static int hammer_recover_btree(hammer_cluster_t cluster,
				hammer_buffer_t buffer, int32_t rec_offset,
				hammer_record_ondisk_t rec);

/*
 * Recover a cluster.  The caller has referenced and locked the cluster.
 * 
 * Generally returns 0 on success and EIO if the recovery was unsuccessful.
 */
int
hammer_recover(hammer_cluster_t cluster)
{
	int buf_no;
	int nbuffers;
	int32_t r;
	u_int32_t bitmap;

	return(0); /* XXX */

	kprintf("HAMMER_RECOVER %d:%d\n",
		cluster->volume->vol_no, cluster->clu_no);
	KKASSERT(cluster->ondisk->synchronized_tid);

	nbuffers = cluster->ondisk->clu_limit / HAMMER_BUFSIZE;
	hammer_modify_cluster(cluster);

	/*
	 * Re-initialize the A-lists.
	 */
	hammer_alist_init(&cluster->alist_master, 1, nbuffers - 1,
			  HAMMER_ASTATE_FREE);
	hammer_alist_init(&cluster->alist_btree,
			  HAMMER_FSBUF_MAXBLKS,
			  (nbuffers - 1) * HAMMER_FSBUF_MAXBLKS,
			  HAMMER_ASTATE_ALLOC);
	hammer_alist_init(&cluster->alist_mdata,
			  HAMMER_FSBUF_MAXBLKS,
			  (nbuffers - 1) * HAMMER_FSBUF_MAXBLKS,
			  HAMMER_ASTATE_ALLOC);
	hammer_alist_init(&cluster->alist_record,
			  HAMMER_FSBUF_MAXBLKS,
			  (nbuffers - 1) * HAMMER_FSBUF_MAXBLKS,
			  HAMMER_ASTATE_ALLOC);

	/*
	 * Scan the cluster's clu_record_buf_bitmap, reserve record buffers
	 * from the master bitmap before we try to recover their data.  Free
	 * the block of records to alist_record.
	 *
	 * We need to mark the blocks as free in alist_record so future
	 * allocations will dive into the buffer A-list's, but we don't 
	 * want to destroy the underlying buffer A-list's.  Because the
	 * meta data in cluster->alist_record indicates state 00 (all-allocated
	 * but not initialized), it will not dive down into the buffer when
	 * freeing the entire buffer.
	 */
	for (buf_no = 1; buf_no < nbuffers; ++buf_no) {
		bitmap = cluster->ondisk->clu_record_buf_bitmap[buf_no >> 5];
		if (bitmap == 0) {
			buf_no = ((buf_no + 32) & ~31) - 1;
			continue;
		}
		if ((bitmap & (1 << (buf_no & 31))) == 0)
			continue;
		r = hammer_alist_alloc_fwd(&cluster->alist_master, 1, buf_no);
		KKASSERT(r == buf_no);
		hammer_alist_free(&cluster->alist_record,
				  buf_no * HAMMER_FSBUF_MAXBLKS,
				  HAMMER_FSBUF_MAXBLKS);
	}

	/*
	 * Scan the cluster's clu_record_buf_bitmap, reassign buffers
	 * from alist_master to alist_record, and reallocate individual
	 * records and any related data reference if they meet the critera.
	 */
	for (buf_no = 1; buf_no < nbuffers; ++buf_no) {
		bitmap = cluster->ondisk->clu_record_buf_bitmap[buf_no >> 5];
		if (bitmap == 0) {
			buf_no = ((buf_no + 32) & ~31) - 1;
			continue;
		}
		if ((bitmap & (1 << (buf_no & 31))) == 0)
			continue;
		hammer_recover_buffer_stage1(cluster, buf_no);
	}

	/*
	 * The cluster is now in good enough shape that general allocations
	 * are possible.  Construct an empty B-Tree root.
	 */
	{
		hammer_node_t croot;
		int error;

		croot = hammer_alloc_btree(cluster, &error);
		if (error == 0) {
			hammer_modify_node(croot);
			bzero(croot->ondisk, sizeof(*croot->ondisk));
			croot->ondisk->count = 0;
			croot->ondisk->type = HAMMER_BTREE_TYPE_LEAF;
			cluster->ondisk->clu_btree_root = croot->node_offset;
			hammer_rel_node(croot);
		}
	}

	/*
	 * Scan the cluster's clu_record_buf_bitmap again and regenerate
	 * the B-Tree.
	 *
	 * XXX B-tree record for cluster-push
	 */
	for (buf_no = 1; buf_no < nbuffers; ++buf_no) {
		bitmap = cluster->ondisk->clu_record_buf_bitmap[buf_no >> 5];
		if (bitmap == 0) {
			buf_no = ((buf_no + 32) & ~31) - 1;
			continue;
		}
		if ((bitmap & (1 << (buf_no & 31))) == 0)
			continue;
		hammer_recover_buffer_stage2(cluster, buf_no);
	}
	kprintf("HAMMER_RECOVER DONE %d:%d\n",
		cluster->volume->vol_no, cluster->clu_no);

	/*
	 * Validate the parent cluster pointer. XXX
	 */
	return(0);
}

/*
 * Reassign buf_no as a record buffer and recover any related data
 * references.
 */
static void
hammer_recover_buffer_stage1(hammer_cluster_t cluster, int32_t buf_no)
{
	hammer_record_ondisk_t rec;
	hammer_buffer_t buffer;
	int32_t rec_no;
	int32_t rec_offset;
	int error;

	kprintf("recover buffer1 %d:%d:%d\n",
		cluster->volume->vol_no,
		cluster->clu_no, buf_no);
	buffer = hammer_get_buffer(cluster, buf_no, 0, &error);
	if (error) {
		/*
		 * If we are unable to access the buffer leave it in a
		 * reserved state on the master alist.
		 */
		kprintf("hammer_recover_buffer_stage1: error "
			"recovering %d:%d:%d\n",
			cluster->volume->vol_no, cluster->clu_no, buf_no);
		return;
	}

	/*
	 * Recover the buffer, scan and validate allocated records.  Records
	 * which cannot be recovered are freed.
	 */
	hammer_modify_buffer(buffer);
	hammer_alist_recover(&buffer->alist, 0, 0, HAMMER_RECORD_NODES);
	rec_no = -1;
	for (;;) {
		rec_no = hammer_alist_find(&buffer->alist, rec_no + 1,
					   HAMMER_RECORD_NODES);
		if (rec_no == HAMMER_ALIST_BLOCK_NONE)
			break;
#if 0
		kprintf("recover record %d:%d:%d %d\n",
			cluster->volume->vol_no,
			cluster->clu_no, buf_no, rec_no);
#endif
		rec_offset = offsetof(union hammer_fsbuf_ondisk,
				      record.recs[rec_no]);
		rec_offset += buf_no * HAMMER_BUFSIZE;
		rec = &buffer->ondisk->record.recs[rec_no];
		error = hammer_recover_record(cluster, buffer, rec_offset, rec);
		if (error) {
			kprintf("hammer_recover_record: failed %d:%d@%d\n",
				cluster->clu_no, buffer->buf_no, rec_offset);
			hammer_alist_free(&buffer->alist, rec_no, 1);
		}
	}
	hammer_rel_buffer(buffer, 0);
}

/*
 * Recover a record, at least into a state that doesn't blow up the
 * filesystem.  Returns 0 on success, non-zero if the record is
 * unrecoverable.
 */
static int
hammer_recover_record(hammer_cluster_t cluster, hammer_buffer_t buffer,
			     int32_t rec_offset, hammer_record_ondisk_t rec)
{
	hammer_buffer_t dbuf;
	hammer_tid_t syncid = cluster->ondisk->synchronized_tid;
	int32_t data_offset;
	int32_t data_len;
	int32_t nblks;
	int32_t dbuf_no;
	int32_t dblk_no;
	int32_t base_blk;
	int32_t r;
	int error = 0;

	/*
	 * Discard records created after the synchronization point and
	 * undo any deletions made after the synchronization point.
	 */
	if (rec->base.base.create_tid > syncid) {
		kprintf("recover record: syncid too large %016llx/%016llx\n",
			rec->base.base.create_tid, syncid);
		return(EINVAL);
	}

	if (rec->base.base.delete_tid > syncid)
		rec->base.base.delete_tid = 0;

	/*
	 * Validate the record's B-Tree key
	 */
	if (rec->base.base.rec_type != HAMMER_RECTYPE_CLUSTER) {
		if (hammer_btree_cmp(&rec->base.base,
				     &cluster->ondisk->clu_btree_beg) < 0)  {
			kprintf("recover record: range low\n");
			return(EINVAL);
		}
		if (hammer_btree_cmp(&rec->base.base,
				     &cluster->ondisk->clu_btree_end) >= 0)  {
			kprintf("recover record: range high\n");
			return(EINVAL);
		}
	}

	/*
	 * Validate the record's data.  If the offset is 0 there is no data
	 * (or it is zero-fill) and we can return success immediately.
	 * Otherwise make sure everything is ok.
	 */
	data_offset = rec->base.data_offset;
	data_len = rec->base.data_len;

	if (data_len == 0)
		rec->base.data_offset = data_offset = 0;
	if (data_offset == 0)
		goto done;

	/*
	 * Non-zero data offset, recover the data
	 */
	if (data_offset < HAMMER_BUFSIZE ||
	    data_offset >= cluster->ondisk->clu_limit ||
	    data_len < 0 || data_len > HAMMER_MAXDATA ||
	    data_offset + data_len > cluster->ondisk->clu_limit) {
		kprintf("recover record: bad offset/len %d/%d\n",
			data_offset, data_len);
		return(EINVAL);
	}

	/*
	 * Check data_offset relative to rec_offset
	 */
	if (data_offset < rec_offset && data_offset + data_len > rec_offset) {
		kprintf("recover record: bad offset: overlapping1\n");
		return(EINVAL);
	}
	if (data_offset >= rec_offset &&
	    data_offset < rec_offset + sizeof(struct hammer_base_record)) {
		kprintf("recover record: bad offset: overlapping2\n");
		return(EINVAL);
	}

	/*
	 * Check for data embedded in the record
	 */
	if (data_offset >= rec_offset &&
	    data_offset < rec_offset + HAMMER_RECORD_SIZE) {
		if (data_offset + data_len > rec_offset + HAMMER_RECORD_SIZE) {
			kprintf("recover record: bad offset: overlapping3\n");
			return(EINVAL);
		}
		goto done;
	}

	/*
	 * Recover the allocated data either out of the cluster's master alist
	 * or as a buffer sub-allocation.
	 */
	if ((data_len & HAMMER_BUFMASK) == 0) {
		if (data_offset & HAMMER_BUFMASK) {
			kprintf("recover record: bad offset: unaligned\n");
			return(EINVAL);
		}
		nblks = data_len / HAMMER_BUFSIZE;
		dbuf_no = data_offset / HAMMER_BUFSIZE;

		r = hammer_alist_alloc_fwd(&cluster->alist_master,
					   nblks, dbuf_no);
		if (r == HAMMER_ALIST_BLOCK_NONE) {
			kprintf("recover record: cannot recover offset1\n");
			return(EINVAL);
		}
		if (r != dbuf_no) {
			kprintf("recover record: cannot recover offset2\n");
			hammer_alist_free(&cluster->alist_master, r, nblks);
			return(EINVAL);
		}
	} else {
		if ((data_offset & ~HAMMER_BUFMASK) !=
		    ((data_offset + data_len - 1) & ~HAMMER_BUFMASK)) {
			kprintf("recover record: overlaps multiple bufs\n");
			return(EINVAL);
		}
		if ((data_offset & HAMMER_BUFMASK) <
		    sizeof(struct hammer_fsbuf_head)) {
			kprintf("recover record: data in header area\n");
			return(EINVAL);
		}
		if (data_offset & HAMMER_DATA_BLKMASK) {
			kprintf("recover record: data blk unaligned\n");
			return(EINVAL);
		}

		/*
		 * Ok, recover the space in the data buffer.
		 */
		dbuf_no = data_offset / HAMMER_BUFSIZE;
		r = hammer_alist_alloc_fwd(&cluster->alist_master, 1, dbuf_no);
		if (r != dbuf_no && r != HAMMER_ALIST_BLOCK_NONE)
			hammer_alist_free(&cluster->alist_master, r, 1);
		if (r == dbuf_no) {
			/*
			 * This is the first time we've tried to recover
			 * data in this data buffer, reinit it (but don't
			 * zero it out, obviously).
			 *
			 * Calling initbuffer marks the data blocks within
			 * the buffer as being free.
			 */
			dbuf = hammer_get_buffer(cluster, dbuf_no,
						 0, &error);
			if (error == 0) {
				hammer_modify_buffer(dbuf);
				hammer_initbuffer(&dbuf->alist,	
						  &dbuf->ondisk->head,
						  HAMMER_FSBUF_DATA);
				dbuf->buf_type = HAMMER_FSBUF_DATA;
			}
			base_blk = dbuf_no * HAMMER_FSBUF_MAXBLKS;
			hammer_alist_free(&cluster->alist_mdata, base_blk,
					  HAMMER_DATA_NODES);
		} else {
			/*
			 * We've seen this data buffer before.
			 */
			dbuf = hammer_get_buffer(cluster, dbuf_no,
						 0, &error);
		}
		if (error) {
			kprintf("recover record: data: getbuf failed\n");
			return(EINVAL);
		}

		if (dbuf->buf_type != HAMMER_FSBUF_DATA) {
			hammer_rel_buffer(dbuf, 0);
			kprintf("recover record: data: wrong buffer type\n");
			return(EINVAL);
		}

		/*
		 * Figure out the data block number and number of blocks.
		 */
		nblks = (data_len + HAMMER_DATA_BLKMASK) & ~HAMMER_DATA_BLKMASK;
		nblks /= HAMMER_DATA_BLKSIZE;
		dblk_no = ((data_offset & HAMMER_BUFMASK) - offsetof(union hammer_fsbuf_ondisk, data.data)) / HAMMER_DATA_BLKSIZE;
		if ((data_offset & HAMMER_BUFMASK) != offsetof(union hammer_fsbuf_ondisk, data.data[dblk_no])) {
			kprintf("dblk_no %d does not match data_offset %d/%d\n",
				dblk_no,
				offsetof(union hammer_fsbuf_ondisk, data.data[dblk_no]),
				(data_offset & HAMMER_BUFMASK));
			hammer_rel_buffer(dbuf, 0);
			kprintf("recover record: data: not block aligned\n");
			Debugger("bad data");
			return(EINVAL);
		}
		dblk_no += dbuf_no * HAMMER_FSBUF_MAXBLKS;
		r = hammer_alist_alloc_fwd(&cluster->alist_mdata, nblks, dblk_no);
		if (r != dblk_no) {
			if (r != HAMMER_ALIST_BLOCK_NONE)
				hammer_alist_free(&cluster->alist_mdata, r, nblks);
			hammer_rel_buffer(dbuf, 0);
			kprintf("recover record: data: unable to realloc\n");
			return(EINVAL);
		}
		hammer_rel_buffer(dbuf, 0);
	}
done:
	return(0);
}

/*
 * Rebuild the B-Tree for the records residing in the specified buffer.
 */
static void
hammer_recover_buffer_stage2(hammer_cluster_t cluster, int32_t buf_no)
{
	hammer_record_ondisk_t rec;
	hammer_buffer_t buffer;
	int32_t rec_no;
	int32_t rec_offset;
	int error;

	buffer = hammer_get_buffer(cluster, buf_no, 0, &error);
	if (error) {
		/*
		 * If we are unable to access the buffer leave it in a
		 * reserved state on the master alist.
		 */
		kprintf("hammer_recover_buffer_stage2: error "
			"recovering %d:%d:%d\n",
			cluster->volume->vol_no, cluster->clu_no, buf_no);
		return;
	}

	/*
	 * Recover the buffer, scan and validate allocated records.  Records
	 * which cannot be recovered are freed.
	 */
	rec_no = -1;
	for (;;) {
		rec_no = hammer_alist_find(&buffer->alist, rec_no + 1,
					   HAMMER_RECORD_NODES);
		if (rec_no == HAMMER_ALIST_BLOCK_NONE)
			break;
		rec_offset = offsetof(union hammer_fsbuf_ondisk,
				      record.recs[rec_no]);
		rec_offset += buf_no * HAMMER_BUFSIZE;
		rec = &buffer->ondisk->record.recs[rec_no];
		error = hammer_recover_btree(cluster, buffer, rec_offset, rec);
		if (error) {
			kprintf("hammer_recover_btree: failed %d:%d@%d\n",
				cluster->clu_no, buffer->buf_no, rec_offset);
			/* XXX free the record and its data? */
			/*hammer_alist_free(&buffer->alist, rec_no, 1);*/
		}
	}
	hammer_rel_buffer(buffer, 0);
}

static int
hammer_recover_btree(hammer_cluster_t cluster, hammer_buffer_t buffer,
		      int32_t rec_offset, hammer_record_ondisk_t rec)
{
	struct hammer_cursor cursor;
	union hammer_btree_elm elm;
	hammer_cluster_t ncluster;
	int error = 0;

	/*
	 * Check for a spike record.
	 */
	kprintf("hammer_recover_btree cluster %p (%d) type %d\n",
		cluster, cluster->clu_no, rec->base.base.rec_type);
	if (rec->base.base.rec_type == HAMMER_RECTYPE_CLUSTER) {
		hammer_volume_t ovolume = cluster->volume;
		hammer_volume_t nvolume;

		nvolume = hammer_get_volume(ovolume->hmp, rec->spike.vol_no,
					    &error);
		if (error)
			return(error);
		ncluster = hammer_get_cluster(nvolume, rec->spike.clu_no,
					      &error, 0);
		hammer_rel_volume(nvolume, 0);
		if (error)
			return(error);

		/*
		 * Validate the cluster.  Allow the offset to be fixed up.
		 */
		if (ncluster->ondisk->clu_btree_parent_vol_no != ovolume->vol_no ||
		    ncluster->ondisk->clu_btree_parent_clu_no != cluster->clu_no) {
			kprintf("hammer_recover: Bad cluster spike hookup: "
				"%d:%d != %d:%d\n",
				ncluster->ondisk->clu_btree_parent_vol_no,
				ncluster->ondisk->clu_btree_parent_clu_no,
				ovolume->vol_no,
				ovolume->vol_no);
			error = EINVAL;
			hammer_rel_cluster(ncluster, 0);
			return(error);
		}
	} else {
		ncluster = NULL;
	}

	/*
	 * Locate the insertion point.  Note that we are using the cluster-
	 * localized cursor init so parent will start out NULL.
	 */
	kprintf("hammer_recover_btree init_cursor_cluster cluster %p (%d) type %d ncluster %p\n",
		cluster, cluster->clu_no, rec->base.base.rec_type, ncluster);
	error = hammer_init_cursor_cluster(&cursor, cluster);
	if (error)
		goto failed;
	KKASSERT(cursor.node);
	if (ncluster)
		cursor.key_beg = ncluster->ondisk->clu_btree_beg;
	else
		cursor.key_beg = rec->base.base;
	cursor.flags |= HAMMER_CURSOR_INSERT;

	error = hammer_btree_lookup(&cursor);
	KKASSERT(error != EDEADLK);
	KKASSERT(cursor.node);
	if (error == 0) {
		kprintf("hammer_recover_btree: Duplicate record\n");
		hammer_print_btree_elm(&cursor.node->ondisk->elms[cursor.index], HAMMER_BTREE_TYPE_LEAF, cursor.index);
		Debugger("duplicate record");
	}
	if (error != ENOENT)
		goto failed;

	if (ncluster) {
		/*
		 * Spike record
		 */
		kprintf("recover spike clu %d %016llx-%016llx\n",
			ncluster->clu_no,
			ncluster->ondisk->clu_btree_beg.obj_id,
			ncluster->ondisk->clu_btree_end.obj_id);
		error = hammer_btree_insert_cluster(&cursor, ncluster,
						    rec_offset);
		kprintf("recover spike record error %d\n", error);
		KKASSERT(error != EDEADLK);
		if (error)
			Debugger("spike recovery");
	} else {
		/*
		 * Normal record
		 */
		kprintf("recover recrd clu %d %016llx\n",
			cluster->clu_no, rec->base.base.obj_id);
		elm.leaf.base = rec->base.base;
		elm.leaf.rec_offset = rec_offset;
		elm.leaf.data_offset = rec->base.data_offset;
		elm.leaf.data_len = rec->base.data_len;
		elm.leaf.data_crc = rec->base.data_crc;

		error = hammer_btree_insert(&cursor, &elm);
		KKASSERT(error != EDEADLK);
	}

	if (error) {
		kprintf("hammer_recover_btree: insertion failed\n");
	}

failed:
	if (ncluster)
		hammer_rel_cluster(ncluster, 0);
	hammer_done_cursor(&cursor);
	return(error);
}

