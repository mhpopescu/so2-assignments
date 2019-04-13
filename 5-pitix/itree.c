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
	if (block < INODE_DIRECT_DATA_BLOCKS && (!block || pii->direct_db[block])) {
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
		bl_bh = sb_getblk(inode->i_sb, psb->dzone_block + b);
		lock_buffer(bl_bh);
		memset(bl_bh->b_data, 0, bl_bh->b_size);
		set_buffer_uptodate(bl_bh);
		unlock_buffer(bl_bh);
		mark_buffer_dirty_inode(bl_bh, inode);

		map_bh(bh, sb, psb->dzone_block + b);
		set_buffer_new(bl_bh);

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

			*((__u16 *)bhh->b_data + block - INODE_DIRECT_DATA_BLOCKS) = b;
			mark_buffer_dirty(bhh);
			brelse(bhh);
		}
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

	block_truncate_page(inode->i_mapping, 0, pitix_get_block);

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		if (pii->direct_db[i]) {
			pitix_free_block(sb, pii->direct_db[i]);
			pii->direct_db[i] = 0;
		}
	inode->i_mtime = inode->i_ctime = current_time(inode);
	mark_inode_dirty(inode);
	if (pii->indirect_db) {
		struct buffer_head *bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);

		if (!bh)
			printk(LOG_LEVEL "Unable to read block\n");

		b = (__u16 *)bh->b_data;
		for (i = 0; i < sb->s_blocksize/2; ++i) {
			// FIXME check if it is still allocated
			if (!*b)
				break;
			pitix_free_block(sb, *b);
			b++;
		}
		memset(bh->b_data, 0, sb->s_blocksize);
		mark_buffer_dirty_inode(bh, inode);
	}

	pitix_free_block(sb, pii->indirect_db);
	pii->indirect_db = 0;

}