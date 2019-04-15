// SPDX-License-Identifier: GPL-2.0

/*
 * bitmap.c - contains the code that handles the inode and block bitmaps
 *
 * INSPIRED FROM linux/fs/pitix/bitmap.c
 *
 */

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

/* Pitix does not have unsigned long addr size so cast them */
#define pitix_set_bit(nr, addr)		\
	__set_bit((nr), (unsigned long *)(addr))
#define pitix_test_and_clear_bit(nr, addr) \
	__test_and_clear_bit((nr), (unsigned long *)(addr))
#define pitix_find_first_zero_bit(addr, size) \
	find_first_zero_bit((unsigned long *)(addr), (size))

static DEFINE_SPINLOCK(bitmap_lock);

/*
 * Returns a free inode number for a new inode
 */
int pitix_alloc_inode(struct super_block *sb)
{
	int j = 0;

	struct pitix_super_block *psb = pitix_sb(sb);
	int max_inodes = get_inodes(sb);

	spin_lock(&bitmap_lock);
	j = pitix_find_first_zero_bit(psb->imap, max_inodes);

	if (j <= max_inodes) {
		pitix_set_bit(j, psb->imap);
		psb->ffree--;
		spin_unlock(&bitmap_lock);
		mark_buffer_dirty(psb->imap_bh);
		goto out_alloc_inode;
	}

	spin_unlock(&bitmap_lock);
	printk(LOG_LEVEL "no more free inodes\n");

out_alloc_inode:
	return j;
}

/*
 * Mark inode number as unused
 */
void pitix_free_inode(struct super_block *sb, int ino)
{
	struct pitix_super_block *psb = pitix_sb(sb);

	if (ino < 1 || ino > get_inodes(sb)) {
		printk(LOG_LEVEL "inode 0 or nonexistent inode\n");
		return;
	}

	spin_lock(&bitmap_lock);
	if (!pitix_test_and_clear_bit(ino, psb->imap))
		printk(LOG_LEVEL "ino %d already cleared\n", ino);
	psb->ffree++;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(psb->imap_bh);
}

/*
 * Returns a free block number for a new block
 */
int pitix_alloc_block(struct super_block *sb)
{
	int j = 0;

	struct pitix_super_block *psb = pitix_sb(sb);
	int max_blocks = get_blocks(sb);

	spin_lock(&bitmap_lock);
	j = pitix_find_first_zero_bit(psb->dmap, max_blocks);
	if (j < max_blocks) {
		pitix_set_bit(j, psb->dmap);
		psb->bfree--;
		spin_unlock(&bitmap_lock);
		mark_buffer_dirty(psb->dmap_bh);
		goto out_alloc_block;
	}

	spin_unlock(&bitmap_lock);
	printk(LOG_LEVEL "no more free blocks\n");

out_alloc_block:
	return j;
}

/*
 * Mark block number as unused
 */
void pitix_free_block(struct super_block *sb, int block)
{
	struct pitix_super_block *psb = pitix_sb(sb);

	if (block <= 0 || (block > get_blocks(sb))) {
		printk(LOG_LEVEL "Trying to free block not in datazone\n");
		return;
	}

	spin_lock(&bitmap_lock);
	if (!pitix_test_and_clear_bit(block, psb->dmap)) {
		printk(LOG_LEVEL "(%s:%d): bit already cleared\n",
			sb->s_id, block);
		spin_unlock(&bitmap_lock);
		return;
	}
	psb->bfree++;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(psb->dmap_bh);
}

/*
 * Count number of blocks used by an inode.
 * Used for stat
 */
int count_blocks(struct inode *inode)
{
	struct pitix_inode_info *pii = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct buffer_head *bh;
	int i, ret = 0;
	__u16 *b;

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS && pii->direct_db[i]; ++i)
		ret++;

	if (pii->indirect_db) {
		bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
		if (!bh) {
			printk(LOG_LEVEL "Unable to read block\n");
			goto out_count;
		}

		for (i = 0; i < sb->s_blocksize/2; ++i) {
			b = (__u16 *)bh->b_data + i;
			if (!*b)
				break;
			ret++;
		}

		brelse(bh);
		ret++;
	}

out_count:
	return ret;
}
