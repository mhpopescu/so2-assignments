// SPDX-License-Identifier: GPL-2.0

#include <linux/buffer_head.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "pitix.h"

typedef u16 block_t;
enum {DIRECT = 7, DEPTH = 4};	/* Have triple indirect */

typedef struct {
	block_t	*p;
	block_t	key;
	struct buffer_head *bh;
} Indirect;

#define DIRCOUNT 7
#define INDIRCOUNT(sb) (1 << ((sb)->s_blocksize_bits - 2))

static DEFINE_RWLOCK(pointers_lock);

// static inline block_t *i_data(struct inode *inode)
// {
// 	return (block_t *)pitix_i(inode)->direct_data_blocks;
// }

// static inline void add_chain(Indirect *p, struct buffer_head *bh, block_t *v)
// {
// 	p->key = *(p->p = v);
// 	p->bh = bh;
// }

// static inline int verify_chain(Indirect *from, Indirect *to)
// {
// 	while (from <= to && from->key == *from->p)
// 		from++;
// 	return (from > to);
// }

// static inline Indirect *get_branch(struct inode *inode,
// 					int depth,
// 					int *offsets,
// 					Indirect chain[DEPTH],
// 					int *err)
// {
// 	struct super_block *sb = inode->i_sb;
// 	Indirect *p = chain;
// 	struct buffer_head *bh;

// 	*err = 0;
// 	/* i_data is not going away, no lock needed */
// 	add_chain (chain, NULL, i_data(inode) + *offsets);
// 	if (!p->key)
// 		goto no_block;
// 	while (--depth) {
// 		bh = sb_bread(sb, p->key);
// 		if (!bh)
// 			goto failure;
// 		read_lock(&pointers_lock);
// 		if (!verify_chain(chain, p))
// 			goto changed;
// 		add_chain(++p, bh, (block_t *)bh->b_data + *++offsets);
// 		read_unlock(&pointers_lock);
// 		if (!p->key)
// 			goto no_block;
// 	}
// 	return NULL;

// changed:
// 	read_unlock(&pointers_lock);
// 	brelse(bh);
// 	*err = -EAGAIN;
// 	goto no_block;
// failure:
// 	*err = -EIO;
// no_block:
// 	return p;
// }

// static int block_to_path(struct inode *inode, long block, int offsets[DEPTH])
// {
// 	int n = 0;
// 	struct super_block *sb = inode->i_sb;

// 	if (block < 0) {
// 		printk(LOG_LEVEL "PITIX-fs: block_to_path: block %ld < 0 on dev %pg\n",
// 			block, sb->s_bdev);
// 	} /*else if ((u64)block * (u64)sb->s_blocksize >=
// 			minix_sb(sb)->s_max_size) {
// 		if (printk_ratelimit())
// 			printk("PITIX-fs: block_to_path: "
// 			       "block %ld too big on dev %pg\n",
// 				block, sb->s_bdev);
// 	}*/ else if (block < DIRCOUNT) {
// 		offsets[n++] = block;
// 	} else if ((block -= DIRCOUNT) < INDIRCOUNT(sb)) {
// 		offsets[n++] = DIRCOUNT;
// 		offsets[n++] = block;
// 	} else if ((block -= INDIRCOUNT(sb)) < INDIRCOUNT(sb) * INDIRCOUNT(sb)) {
// 		offsets[n++] = DIRCOUNT + 1;
// 		offsets[n++] = block / INDIRCOUNT(sb);
// 		offsets[n++] = block % INDIRCOUNT(sb);
// 	} else {
// 		block -= INDIRCOUNT(sb) * INDIRCOUNT(sb);
// 		offsets[n++] = DIRCOUNT + 2;
// 		offsets[n++] = (block / INDIRCOUNT(sb)) / INDIRCOUNT(sb);
// 		offsets[n++] = (block / INDIRCOUNT(sb)) % INDIRCOUNT(sb);
// 		offsets[n++] = block % INDIRCOUNT(sb);
// 	}
// 	return n;
// }

// static int alloc_branch(struct inode *inode,
// 			     int num,
// 			     int *offsets,
// 			     Indirect *branch)
// {
// 	int n = 0;
// 	int i;
// 	int parent = pitix_alloc_block(inode->i_sb);

// 	branch[0].key = parent;
// 	if (parent) for (n = 1; n < num; n++) {
// 		struct buffer_head *bh;
// 		/* Allocate the next block */
// 		int nr = pitix_alloc_block(inode->i_sb);
// 		if (!nr)
// 			break;
// 		branch[n].key = nr;
// 		bh = sb_getblk(inode->i_sb, parent);
// 		lock_buffer(bh);
// 		memset(bh->b_data, 0, bh->b_size);
// 		branch[n].bh = bh;
// 		branch[n].p = (block_t*) bh->b_data + offsets[n];
// 		*branch[n].p = branch[n].key;
// 		set_buffer_uptodate(bh);
// 		unlock_buffer(bh);
// 		mark_buffer_dirty_inode(bh, inode);
// 		parent = nr;
// 	}
// 	if (n == num)
// 		return 0;

// 	/* Allocation failed, free what we already allocated */
// 	for (i = 1; i < n; i++)
// 		bforget(branch[i].bh);
// 	for (i = 0; i < n; i++)
// 		pitix_free_block(inode->i_sb, branch[i].key);
// 	return -ENOSPC;
// }

// static inline int splice_branch(struct inode *inode,
// 				     Indirect chain[DEPTH],
// 				     Indirect *where,
// 				     int num)
// {
// 	int i;

// 	write_lock(&pointers_lock);

// 	/* Verify that place we are splicing to is still there and vacant */
// 	if (!verify_chain(chain, where-1) || *where->p)
// 		goto changed;

// 	*where->p = where->key;

// 	write_unlock(&pointers_lock);

// 	/* We are done with atomic stuff, now do the rest of housekeeping */

// 	inode->i_ctime = current_time(inode);

// 	/* had we spliced it onto indirect block? */
// 	if (where->bh)
// 		mark_buffer_dirty_inode(where->bh, inode);

// 	mark_inode_dirty(inode);
// 	return 0;

// changed:
// 	write_unlock(&pointers_lock);
// 	for (i = 1; i < num; i++)
// 		bforget(where[i].bh);
// 	for (i = 0; i < num; i++)
// 		pitix_free_block(inode->i_sb, where[i].key);
// 	return -EAGAIN;
// }

int pitix_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh, int create)
{
	struct pitix_super_block *psb = pitix_sb(inode->i_sb);
	// pr_info("pitix_get_block inode=[%ld] block=[%lld]\n", inode->i_ino, block);

	if (block < get_blocks(inode->i_sb))
		map_bh(bh, inode->i_sb, psb->dzone_block + block);
	return 0;
// 	int err = -EIO;
// 	int offsets[DEPTH];
// 	Indirect chain[DEPTH];
// 	Indirect *partial;
// 	int left;
// 	int depth = block_to_path(inode, block, offsets);

// 	if (depth == 0)
// 		goto out;

// reread:
// 	partial = get_branch(inode, depth, offsets, chain, &err);

// 	/* Simplest case - block found, no allocation needed */
// 	if (!partial) {
// got_it:
// 		map_bh(bh, inode->i_sb, chain[depth-1].key);
// 		/* Clean up and exit */
// 		partial = chain+depth-1; /* the whole chain */
// 		goto cleanup;
// 	}

// 	/* Next simple case - plain lookup or failed read of indirect block */
// 	if (!create || err == -EIO) {
// cleanup:
// 		while (partial > chain) {
// 			brelse(partial->bh);
// 			partial--;
// 		}
// out:
// 		return err;
// 	}

// 	/*
// 	 * Indirect block might be removed by truncate while we were
// 	 * reading it. Handling of that case (forget what we've got and
// 	 * reread) is taken out of the main path.
// 	 */
// 	if (err == -EAGAIN)
// 		goto changed;

// 	left = (chain + depth) - partial;
// 	err = alloc_branch(inode, left, offsets+(partial-chain), partial);
// 	if (err)
// 		goto cleanup;

// 	if (splice_branch(inode, chain, partial, left) < 0)
// 		goto changed;

// 	set_buffer_new(bh);
// 	goto got_it;

// changed:
// 	while (partial > chain) {
// 		brelse(partial->bh);
// 		partial--;
// 	}
// 	goto reread;
}