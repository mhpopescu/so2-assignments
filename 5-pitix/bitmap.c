// SPDX-License-Identifier: GPL-2.0

/*  bitmap.c
 *
 *  INSPIRED FROM linux/fs/pitix/bitmap.c
 *
 */

/* bitmap.c contains the code that handles the inode and block bitmaps */

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

static DEFINE_SPINLOCK(bitmap_lock);

#define pitix_test_and_set_bit(nr, addr)	\
	__test_and_set_bit((nr), (unsigned long *)(addr))
#define pitix_set_bit(nr, addr)		\
	__set_bit((nr), (unsigned long *)(addr))
#define pitix_test_and_clear_bit(nr, addr) \
	__test_and_clear_bit((nr), (unsigned long *)(addr))
#define pitix_test_bit(nr, addr)		\
	test_bit((nr), (unsigned long *)(addr))
#define pitix_find_first_zero_bit(addr, size) \
	find_first_zero_bit((unsigned long *)(addr), (size))


struct inode *pitix_new_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	struct buffer_head *bh;
	long bits_per_zone = get_blocks(sb);
	struct pitix_super_block *psb = pitix_sb(sb);
	unsigned long j;
	int i;

	if (!inode) {
		// *error = -ENOMEM;
		return NULL;
	}

	j = bits_per_zone;
	bh = NULL;
	// *error = -ENOSPC;
	spin_lock(&bitmap_lock);

	j = pitix_find_first_zero_bit(psb->imap, bits_per_zone);

	if (j >= bits_per_zone) {
		spin_unlock(&bitmap_lock);
		iput(inode);
		return NULL;
	}
	pitix_test_and_set_bit(j, psb->imap);
	spin_unlock(&bitmap_lock);

	mark_buffer_dirty(psb->sb_bh);
	// j += i * bits_per_zone;
	// if (!j || j > psb->s_ninodes) {
	// 	iput(inode);
	// 	return NULL;
	// }
	// FIXME 	MOVE HERE because of make inode_dirty
	// inode_init_owner(inode, dir, mode);

	inode->i_ino = j;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		pitix_i(inode)->direct_db[i] = 0;
	pitix_i(inode)->indirect_db = 0;

	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	// *error = 0;
	return inode;
}

int pitix_alloc_block(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	int bits_per_zone = get_blocks(sb);
	int i;

	int j;

	spin_lock(&bitmap_lock);
	j = pitix_find_first_zero_bit(psb->dmap, bits_per_zone);
	if (j < bits_per_zone) {
		pitix_set_bit(j, psb->dmap);
		spin_unlock(&bitmap_lock);
		mark_buffer_dirty(psb->dmap_bh);
		return j + psb->dzone_block;
	}
	else
		pr_info("BAD pitix_alloc_block\n");

	spin_unlock(&bitmap_lock);
	return 0;
}

void pitix_free_block(struct super_block *sb, int block)
{
	// struct minix_sb_info *sbi = minix_sb(sb);
	struct pitix_super_block *psb = pitix_sb(sb);
	// struct buffer_head *bh;
	int k = sb->s_blocksize_bits + 3;
	unsigned long bit, zone;

// FIXME
//  || block >= sbi->s_nzones
	if (block < psb->dzone_block) {
		printk("Trying to free block not in datazone\n");
		return;
	}
	zone = block - psb->dzone_block + 1;
	bit = zone & ((1<<k) - 1);
	zone >>= k;
	// FIXME
	// if (zone >= sbi->s_zmap_blocks) {
	// 	printk("minix_free_block: nonexistent bitmap buffer\n");
	// 	return;
	// }
	// bh = sbi->s_zmap[zone];
	spin_lock(&bitmap_lock);
	if (!pitix_test_and_clear_bit(bit, psb->dmap_bh))
		printk("pitix_free_block (%s:%d): bit already cleared\n",
		       sb->s_id, block);
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(psb->dmap_bh);
	return;
}
