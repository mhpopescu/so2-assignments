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

int pitix_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);
	__u16 b;
	struct buffer_head *bl_bh;

	// pr_info("pitix_get_block %lld %d\n", block, create);

	/* not sure all checks are needed but respect minix checks */
	if (block < 0) {
		printk(LOG_LEVEL "PITIX-fs: block_to_path: block %lld < 0 on dev %pg\n",
			block, inode->i_sb->s_bdev);
		return -EINVAL;
	} else if (block >= sb->s_blocksize/2 + INODE_DIRECT_DATA_BLOCKS){
		printk(LOG_LEVEL "PITIX-fs: pitix_get_block: "
			       "block %lld too big on dev %pg\n",
				block, inode->i_sb->s_bdev);
		return -EINVAL;
	} 

	if (create)
		goto create;
	if (block < INODE_DIRECT_DATA_BLOCKS) {
		b = psb->dzone_block + pii->direct_db[block];
		map_bh(bh, sb, b);
	} else if (pii->indirect_db) {
		bl_bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
		if (!bl_bh) {
			printk(LOG_LEVEL "Unable to read block\n");
			return -EINVAL;
		}

		b = *((__u16 *)bl_bh->b_data + block - INODE_DIRECT_DATA_BLOCKS);
		b += psb->dzone_block;
		map_bh(bh, sb, b);
		brelse(bl_bh);
	}
create:
	if (create){
		b = pitix_alloc_block(sb);
		if (!b)
			return -ENOMEM;
		
		if (block < INODE_DIRECT_DATA_BLOCKS)
			pii->direct_db[block] = b;
		else {
			int bl;
			if (block == INODE_DIRECT_DATA_BLOCKS) {
				bl = pitix_alloc_block(sb);
				if (!bl)
					return -ENOMEM;
				pii->indirect_db = bl;
			}
			else
				bl = pii->indirect_db;

			struct buffer_head *bhh = sb_bread(sb, psb->dzone_block + bl);
			if (!bhh) {
				printk("Unable to read inode block\n");
			}
			if (block == INODE_DIRECT_DATA_BLOCKS)
				memset(bhh->b_data, 0, bhh->b_size);

			((__u16 *)bhh->b_data)[block - INODE_DIRECT_DATA_BLOCKS] = b;
			mark_buffer_dirty(bhh);
			brelse(bhh);
		}

		bl_bh = sb_getblk(inode->i_sb, psb->dzone_block + b);
		lock_buffer(bl_bh);
		memset(bl_bh->b_data, 0, bl_bh->b_size);
		set_buffer_uptodate(bl_bh);
		unlock_buffer(bl_bh);
		mark_buffer_dirty_inode(bl_bh, inode);

		set_buffer_new(bh);
		map_bh(bh, sb, psb->dzone_block + b);

	}
	return 0;
}

void pitix_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	int i;
	__u16 *b;
	struct pitix_inode_info *pii = pitix_i(inode);

	int block = ((__u32) inode->i_size + sb->s_blocksize -1)/ sb->s_blocksize ;
	// if ((__u32) inode->i_size % sb->s_blocksize == 0)
		// block--;

	block_truncate_page(inode->i_mapping, inode->i_size, pitix_get_block);

	for (i = block; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		if (pii->direct_db[i]) {
			pitix_free_block(sb, pii->direct_db[i]);
			pii->direct_db[i] = 0;
		}

	block -= INODE_DIRECT_DATA_BLOCKS;
	if (block < 0)
		block = 0;
	/* if there are not allocated all direct blocks then indirect is not also */
	if (pii->indirect_db) {
		struct buffer_head *bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);

		if (!bh)
			printk(LOG_LEVEL "Unable to read block\n");

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