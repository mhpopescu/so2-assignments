// SPDX-License-Identifier: GPL-2.0

/*
 * itree.c
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

static int get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh)
{
	__u16 b;
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);
	struct buffer_head *indirect_bh;

	if (block < INODE_DIRECT_DATA_BLOCKS) {
		b = psb->dzone_block + pii->direct_db[block];
		map_bh(bh, sb, b);
		return 0;
	}

	indirect_bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
	if (!indirect_bh) {
		printk(LOG_LEVEL "Unable to read block\n");
		return -EINVAL;
	}

	block -= INODE_DIRECT_DATA_BLOCKS;
	b = *((__u16 *)indirect_bh->b_data + block);
	b += psb->dzone_block;
	map_bh(bh, sb, b);
	brelse(indirect_bh);

	return 0;
}

static int create_block(struct inode *inode, sector_t block,
		struct buffer_head *bh)
{
	__u16 b;
	struct buffer_head *b_bh;
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);


	b = pitix_alloc_block(sb);
	if (!b)
		return -ENOMEM;

	if (block < INODE_DIRECT_DATA_BLOCKS)
		pii->direct_db[block] = b;
	else {
		struct buffer_head *indirect_bh;
		int indirect;
		__u16 *entry;

		if (block == INODE_DIRECT_DATA_BLOCKS) {
			indirect = pitix_alloc_block(sb);
			if (!indirect)
				goto bad_new_block;
			pii->indirect_db = indirect;
		}

		indirect = pii->indirect_db;
		indirect_bh = sb_bread(sb, psb->dzone_block + indirect);
		if (!indirect_bh)
			goto bad_read;

		if (block == INODE_DIRECT_DATA_BLOCKS)
			memset(indirect_bh->b_data, 0, indirect_bh->b_size);

		block -= INODE_DIRECT_DATA_BLOCKS;
		entry = (__u16 *)indirect_bh->b_data;
		entry[block] = b;
		mark_buffer_dirty(indirect_bh);
		brelse(indirect_bh);
	}

	b_bh = sb_getblk(sb, psb->dzone_block + b);
	lock_buffer(b_bh);
	memset(b_bh->b_data, 0, b_bh->b_size);
	set_buffer_uptodate(b_bh);
	unlock_buffer(b_bh);
	mark_buffer_dirty_inode(b_bh, inode);

	set_buffer_new(bh);
	map_bh(bh, sb, psb->dzone_block + b);

	return 0;

bad_read:
	printk("Unable to read inode block\n");
bad_new_block:
	pitix_free_block(sb, b);
	return -ENOMEM;
}

int pitix_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;

	if (block < 0) {
		printk(LOG_LEVEL "PITIX-fs: block_to_path: block %lld < 0 on dev %pg\n",
			block, inode->i_sb->s_bdev);
		return -EINVAL;
	} else if (block >= sb->s_blocksize / 2 + INODE_DIRECT_DATA_BLOCKS) {
		printk(LOG_LEVEL "PITIX-fs: block %lld too big on dev %pg\n",
			block, inode->i_sb->s_bdev);
		return -EINVAL;
	}

	if (create)
		return create_block(inode, block, bh);

	return get_block(inode, block, bh);
}

void pitix_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);
	int block = (__u32) inode->i_size / sb->s_blocksize + 1;
	struct buffer_head *bh;
	__u16 *b;
	int i;

	if ((__u32) inode->i_size % sb->s_blocksize == 0)
		block--;

	block_truncate_page(inode->i_mapping, inode->i_size, pitix_get_block);

	for (i = block; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		if (pii->direct_db[i]) {
			pitix_free_block(sb, pii->direct_db[i]);
			pii->direct_db[i] = 0;
		}

	block -= INODE_DIRECT_DATA_BLOCKS;
	if (block < 0)
		block = 0;

	/* if there are not allocated all direct
	 * blocks then indirect is also not
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
