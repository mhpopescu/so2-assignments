// SPDX-License-Identifier: GPL-2.0

/*
 * itree.c - contains the code that handles blocks mapping
 *
 * INSPIRED FROM linux/fs/minix/itree.c
 *
 * Author: Mihai Popescu mh.popescu12@gmail.com
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

/* Map an already created block */
static int get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh)
{
	__u16 b = 0;
	int err = 0;

	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);
	struct buffer_head *indirect_bh = NULL;

	if (block < INODE_DIRECT_DATA_BLOCKS) {
		b = psb->dzone_block + pii->direct_db[block];
		map_bh(bh, sb, b);
		goto out_map_block;
	}

	indirect_bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
	if (!indirect_bh) {
		printk(LOG_LEVEL "Unable to read block\n");
		err = -EINVAL;
		goto out_map_block;
	}

	block -= INODE_DIRECT_DATA_BLOCKS;
	b = *((__u16 *)indirect_bh->b_data + block);
	b += psb->dzone_block;
	map_bh(bh, sb, b);
	brelse(indirect_bh);

out_map_block:
	return err;
}

/* Map and create a block. Data is set to 0.
 */
static int create_block(struct inode *inode, sector_t block,
		struct buffer_head *bh)
{
	__u16 b = 0;
	struct buffer_head *b_bh = NULL;
	int err = 0;

	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);

	b = pitix_alloc_block(sb);
	if (!b) {
		err = -ENOMEM;
		goto out_create_block;
	}

	if (block < INODE_DIRECT_DATA_BLOCKS)
		pii->direct_db[block] = b;
	else {
		struct buffer_head *indirect_bh;
		int indirect;
		__u16 *entry;

		/* Create indirect block */
		if (block == INODE_DIRECT_DATA_BLOCKS) {
			indirect = pitix_alloc_block(sb);
			if (!indirect) {
				err = -ENOMEM;
				goto bad_new_block;
			}
			pii->indirect_db = indirect;
		}

		indirect = pii->indirect_db;
		indirect_bh = sb_bread(sb, psb->dzone_block + indirect);
		if (!indirect_bh) {
			err = -ENOMEM;
			goto bad_read;
		}

		if (block == INODE_DIRECT_DATA_BLOCKS)
			memset(indirect_bh->b_data, 0, indirect_bh->b_size);

		/* Save inode new block number */
		block -= INODE_DIRECT_DATA_BLOCKS;
		entry = (__u16 *)indirect_bh->b_data;
		entry[block] = b;
		mark_buffer_dirty(indirect_bh);
		brelse(indirect_bh);
	}

	/* Create data block */
	b_bh = sb_getblk(sb, psb->dzone_block + b);
	lock_buffer(b_bh);
	memset(b_bh->b_data, 0, b_bh->b_size);
	set_buffer_uptodate(b_bh);
	unlock_buffer(b_bh);
	mark_buffer_dirty_inode(b_bh, inode);

	/* Map new block */
	set_buffer_new(bh);
	map_bh(bh, sb, psb->dzone_block + b);

out_create_block:
	return err;

bad_read:
	printk("Unable to read inode block\n");
bad_new_block:
	pitix_free_block(sb, b);
	goto out_create_block;
}

/* Function used to map blocks in address space.
 *
 * Blocks number are relative to pitix_super_block->dzone_block.
 * Blocks in [0, INODE_DIRECT_DATA_BLOCKS) are direct blocks and referred
 * by indexes from direct_data_blocks vector.
 * Blocks in [INODE_DIRECT_DATA_BLOCKS, INODE_DIRECT_DATA_BLOCKS + block_size / 2)
 * are referred by indexes from data blocks indicated by indirect_data_block
 */
int pitix_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;
	int err = 0;

	if (block < 0) {
		printk(LOG_LEVEL "PITIX-fs: block_to_path: block %lld < 0 on dev %pg\n",
				block, inode->i_sb->s_bdev);
		err = -EINVAL;
		goto out_get_block;
	} else if (block >= sb->s_blocksize / 2 + INODE_DIRECT_DATA_BLOCKS) {
		printk(LOG_LEVEL "PITIX-fs: block %lld too big on dev %pg\n",
				block, inode->i_sb->s_bdev);
		err = -EINVAL;
		goto out_get_block;
	}

	if (create) {
		err = create_block(inode, block, bh);
		goto out_get_block;
	}

	err = get_block(inode, block, bh);

out_get_block:
	return err;
}

/* Resize inode to a specific size
 * Also useful to empty a file
 */
void pitix_truncate(struct inode *inode)
{
	struct buffer_head *bh = NULL;
	__u16 *b = NULL;
	int i = 0;
	int block = 0;

	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);

	block = (__u32) inode->i_size / sb->s_blocksize + 1;
	if ((__u32) inode->i_size % sb->s_blocksize == 0)
		block--;

	/* Actual resizing */
	block_truncate_page(inode->i_mapping, inode->i_size, pitix_get_block);

	/* Free direct blocks */
	for (i = block; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		if (pii->direct_db[i]) {
			pitix_free_block(sb, pii->direct_db[i]);
			pii->direct_db[i] = 0;
		}

	block -= INODE_DIRECT_DATA_BLOCKS;
	if (block < 0)
		block = 0;

	/* If there are not allocated all direct blocks then indirect
	 * is also not. Otherwise free indirect blocks
	 */
	if (pii->indirect_db) {
		bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);

		if (!bh) {
			printk(LOG_LEVEL "Unable to read block\n");
			return;
		}

		for (i = block; i < sb->s_blocksize/2; ++i) {
			b = (__u16 *)bh->b_data + i;
			if (!*b)
				break;
			pitix_free_block(sb, *b);
		}

		b = (__u16 *)bh->b_data + block;
		memset(b, 0, sb->s_blocksize - block * 2);
		mark_buffer_dirty_inode(bh, inode);
		brelse(bh);

		if (block == 0) {
			pitix_free_block(sb, pii->indirect_db);
			pii->indirect_db = 0;
		}
	}

	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
}
