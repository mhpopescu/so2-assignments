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


struct inode *pitix_new_inode(const struct inode *dir, umode_t mode, int *error)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = new_inode(sb);
	long max_inodes = get_inodes(sb);
	struct pitix_super_block *psb = pitix_sb(sb);
	unsigned long j;
	int i;

	if (!inode) {
		*error = -ENOMEM;
		return NULL;
	}

	j = max_inodes;
	*error = -ENOSPC;
	spin_lock(&bitmap_lock);

	j = pitix_find_first_zero_bit(psb->imap, max_inodes);

	if (j >= max_inodes) {
		spin_unlock(&bitmap_lock);
		iput(inode);
		return NULL;
	}
	pitix_test_and_set_bit(j, psb->imap);
	psb->ffree--;

	spin_unlock(&bitmap_lock);

	mark_buffer_dirty(psb->imap_bh);

	inode_init_owner(inode, dir, mode);
	inode->i_ino = j;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_blocks = 0;

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		pitix_i(inode)->direct_db[i] = 0;
	pitix_i(inode)->indirect_db = 0;

	insert_inode_hash(inode);
	mark_inode_dirty(inode);


	*error = 0;
	return inode;
}

int pitix_alloc_block(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	int max_blocks = get_blocks(sb);
	int j;

	spin_lock(&bitmap_lock);
	j = pitix_find_first_zero_bit(psb->dmap, max_blocks);
	if (j < max_blocks) {
		pitix_set_bit(j, psb->dmap);
		psb->bfree--;	
		spin_unlock(&bitmap_lock);
		mark_buffer_dirty(psb->dmap_bh);
		return j;
	}

	spin_unlock(&bitmap_lock);
	printk(LOG_LEVEL "no more free blocks\n");
	return 0;
}

int count_blocks(struct inode *inode) {
	struct pitix_inode_info *pii = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	int i;

	int ret = 0;
	__u16 *b;

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS && pii->direct_db[i]; ++i)
		ret++;

	if (pii->indirect_db) {
		ret++;

		struct buffer_head *bh = sb_bread(sb, psb->dzone_block + pii->indirect_db);
		if (!bh)
			printk(LOG_LEVEL "Unable to read block\n");

		for (i = 0; i < sb->s_blocksize/2; ++i) {
			b = (__u16 *)bh->b_data + i;

			if (!*b)
				break;
			ret++;
		}
		brelse(bh);
	}
	return ret;
}

void pitix_free_block(struct super_block *sb, int block)
{
	struct pitix_super_block *psb = pitix_sb(sb);
	unsigned long bit, zone;

	if (block <= 0 || (block > get_blocks(sb))) {
		printk(LOG_LEVEL "Trying to free block %d not in datazone\n", block);
		return;
	}

	spin_lock(&bitmap_lock);
	if (!pitix_test_and_clear_bit(block, psb->dmap)) {
		printk(LOG_LEVEL "pitix_free_block (%s:%d): bit already cleared\n",
		       sb->s_id, block);
		spin_unlock(&bitmap_lock);
		return;
	}
	psb->bfree++;	
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(psb->dmap_bh);
	
}

void pitix_free_inode(struct super_block *sb, int ino)
{
	struct pitix_super_block *psb = pitix_sb(sb);

	if (ino < 1 || ino > get_inodes(sb)) {
		printk(LOG_LEVEL "pitix_free_inode: inode 0 or nonexistent inode\n");
		return;
	}

	spin_lock(&bitmap_lock);
	if (!pitix_test_and_clear_bit(ino, psb->imap))
		printk(LOG_LEVEL "pitix_free_inode: ino %d already cleared\n", ino);
	psb->ffree++;
	spin_unlock(&bitmap_lock);
	mark_buffer_dirty(psb->imap_bh);

}