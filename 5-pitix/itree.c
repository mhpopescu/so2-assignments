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

static DEFINE_RWLOCK(pointers_lock);

int pitix_get_block(struct inode *inode, sector_t block,
			struct buffer_head *bh, int create)
{
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct pitix_inode_info *pii = pitix_i(inode);
	__u16 b;

	if (block < 0) {
		printk("PITIX-fs: block_to_path: block %lld < 0 on dev %pg\n",
			block, inode->i_sb->s_bdev);
		return 1;
	} else if (block >= sb->s_blocksize/2 + INODE_DIRECT_DATA_BLOCKS){
		printk("PITIX-fs: pitix_get_block: "
			       "block %lld too big on dev %pg\n",
				block, inode->i_sb->s_bdev);
		return 1;
	} else if (block < INODE_DIRECT_DATA_BLOCKS && (!block || pii->direct_db[block])) {
		b = psb->dzone_block + pii->direct_db[block];
		map_bh(bh, sb, b);
	} else if (pii->indirect_db) {
		struct buffer_head *bl_bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
		if (!bl_bh) {
			printk("Unable to read block\n");
			return 1;
		}

		b = *((__u16 *)bl_bh->b_data + block - INODE_DIRECT_DATA_BLOCKS);
		if (block >= sb->s_blocksize/2 + INODE_DIRECT_DATA_BLOCKS){
			printk("PITIX-fs: pitix_get_block: "
				       "block %lld too big on dev %pg\n",
					block, inode->i_sb->s_bdev);
			return 1;
		}
		b += psb->dzone_block;
		map_bh(bh, sb, b);
		brelse(bl_bh);
	}
	return 0;
}

void pitix_truncate (struct inode *inode)
{
// 	struct super_block *sb = inode->i_sb;
// 	block_t *idata = i_data(inode);
// 	int offsets[DEPTH];
// 	Indirect chain[DEPTH];
// 	Indirect *partial;
// 	block_t nr = 0;
// 	int n;
// 	int first_whole;
// 	long iblock;

// 	iblock = (inode->i_size + sb->s_blocksize -1) >> sb->s_blocksize_bits;
// 	block_truncate_page(inode->i_mapping, inode->i_size, pitix_get_block);

// 	n = block_to_path(inode, iblock, offsets);
// 	if (!n)
// 		return;

// 	if (n == 1) {
// 		free_data(inode, idata+offsets[0], idata + DIRECT);
// 		first_whole = 0;
// 		goto do_indirects;
// 	}

// 	first_whole = offsets[0] + 1 - DIRECT;
// 	partial = find_shared(inode, n, offsets, chain, &nr);
// 	if (nr) {
// 		if (partial == chain)
// 			mark_inode_dirty(inode);
// 		else
// 			mark_buffer_dirty_inode(partial->bh, inode);
// 		free_branches(inode, &nr, &nr+1, (chain+n-1) - partial);
// 	}
// 	/* Clear the ends of indirect blocks on the shared branch */
// 	while (partial > chain) {
// 		free_branches(inode, partial->p + 1, block_end(partial->bh),
// 				(chain+n-1) - partial);
// 		mark_buffer_dirty_inode(partial->bh, inode);
// 		brelse (partial->bh);
// 		partial--;
// 	}
// do_indirects:
// 	/* Kill the remaining (whole) subtrees */
// 	while (first_whole < DEPTH-1) {
// 		nr = idata[DIRECT+first_whole];
// 		if (nr) {
// 			idata[DIRECT+first_whole] = 0;
// 			mark_inode_dirty(inode);
// 			free_branches(inode, &nr, &nr+1, first_whole+1);
// 		}
// 		first_whole++;
// 	}
// 	inode->i_mtime = inode->i_ctime = current_time(inode);
// 	mark_inode_dirty(inode);
}