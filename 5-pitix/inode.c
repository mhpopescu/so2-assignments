// SPDX-License-Identifier: GPL-2.0+

/*
 * PITIX file system
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

MODULE_DESCRIPTION("PITIX filesystem");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

#define PITIX_SUPER_BLOCK	0
#define PITIX_ROOT_INODE	0

struct inode *pitix_alloc_inode(struct super_block *s)
{
	struct pitix_inode_info *pii;

	pii = kzalloc(sizeof (struct pitix_inode_info), GFP_KERNEL);
	if (!pii)
		return NULL;
	inode_init_once(&pii->vfs_inode);

	return &pii->vfs_inode;
}

static void pitix_destroy_inode(struct inode *inode)
{
	kfree(pitix_i(inode));
}

struct pitix_inode *pitix_raw_inode(struct super_block *sb, ino_t ino, struct buffer_head **bh)
{
	int block;
	struct pitix_inode *pi;

	*bh = NULL;
	if (ino > get_inodes(sb)) {
		printk(LOG_LEVEL "Bad inode number on dev %s: %ld is out of range\n",
		       sb->s_id, (long)ino);
		return NULL;
	}

	block = pitix_sb(sb)->izone_block + ino / pitix_inodes_per_block(sb);
	
	*bh = sb_bread(sb, block);
	if (!*bh) {
		printk("Unable to read inode block\n");
		return NULL;
	}

	pi = ((struct pitix_inode *) (*bh)->b_data) + ino % pitix_inodes_per_block(sb);
	return pi;
}

struct inode *pitix_iget(struct super_block *sb, unsigned long inumber)
{
	struct pitix_inode_info *pii;
	struct pitix_inode *raw_inode;
	struct buffer_head *bh;
	struct inode *inode;
	int i;
	struct pitix_super_block *psb = pitix_sb(sb);

	/* Allocate VFS inode. */
	inode = iget_locked(sb, inumber);
	if (inode == NULL) {
		printk(LOG_LEVEL "error aquiring inode\n");
		return ERR_PTR(-ENOMEM);
	}

	raw_inode = pitix_raw_inode(sb, inode->i_ino, &bh);
	if (!raw_inode) {
		iget_failed(inode);
		return ERR_PTR(-EIO);
	}

	/* Fill VFS inode */
	inode->i_mode = raw_inode->mode;
	i_uid_write(inode, raw_inode->uid);
	i_gid_write(inode, raw_inode->gid);
	inode->i_size = raw_inode->size;
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);
	inode->i_mapping->a_ops = &pitix_aops;

	pitix_set_inode(inode, 0);

	pii = pitix_i(inode);
	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		pii->dd_blocks[i] = raw_inode->direct_data_blocks[i];
	pii->id_block = raw_inode->indirect_data_block;

	brelse(bh);
	unlock_new_inode(inode);

	return inode;
}

static void pitix_put_super(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);

	/* Free superblock buffer head. */
	mark_buffer_dirty(psb->sb_bh);
	brelse(psb->sb_bh);

	printk(KERN_DEBUG "released superblock resources\n");
}

int pitix_fill_super(struct super_block *sb, void *data, int silent)
{
	struct pitix_super_block *psb;
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct buffer_head *bh;
	int ret = -EINVAL;
	bh = sb_bread(sb, PITIX_SUPER_BLOCK);
	if (bh == NULL)
		goto out_bad_sb;

	psb = (struct pitix_super_block *) bh->b_data;
	psb->sb_bh = bh; 

	if (psb->magic != PITIX_MAGIC)
		goto out_bad_magic;

	sb->s_fs_info = psb;

	if (!sb_set_blocksize(sb, (1 << psb->block_size_bits)))
		goto out_bad_blocksize;

	sb->s_magic = psb->magic;
	sb->s_op = &pitix_sops;

	psb->imap_bh = sb_bread(sb, psb->imap_block);

	if (psb->imap_bh == NULL)
		goto out_bad_sb;
	psb->imap = (__u8 *)psb->imap_bh->b_data;

	psb->dmap_bh = sb_bread(sb, psb->dmap_block);
	if (psb->dmap_bh == NULL)
		goto out_bad_sb;
	psb->dmap = (__u8 *)psb->dmap_bh->b_data;
	
	root_inode = pitix_iget(sb, PITIX_ROOT_INODE);
	if (!root_inode)
		goto out_bad_inode;

	root_dentry = d_make_root(root_inode);
	if (!root_dentry)
		goto out_iput;
	sb->s_root = root_dentry;

	return 0;

out_iput:
	iput(root_inode);
out_bad_inode:
	printk(LOG_LEVEL "bad inode\n");
out_bad_magic:
	printk(LOG_LEVEL "bad magic number\n");
	brelse(bh);
out_bad_blocksize:
	printk(LOG_LEVEL "bad block size\n");
	sb->s_fs_info = NULL;
out_bad_sb:
	printk(LOG_LEVEL "error reading buffer_head\n");
	return ret;
}

static struct dentry *pitix_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, pitix_fill_super);
}

static struct file_system_type pitix_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "pitix",
	.mount		= pitix_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

/* dir and inode operation structures */

struct address_space_operations pitix_aops = {
	.readpage       = simple_readpage,
	.write_begin    = simple_write_begin,
	.write_end      = simple_write_end,
};

struct file_operations pitix_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.llseek		= generic_file_llseek,
};

struct inode_operations pitix_file_inode_operations = {
	.getattr	= simple_getattr,
};

struct super_operations pitix_sops = {
	.statfs		= simple_statfs,
	.put_super	= pitix_put_super,
	.alloc_inode	= pitix_alloc_inode,
	.destroy_inode	= pitix_destroy_inode,
	/* TODO 7/1:	= set write_inode function. */
	// .write_inode	= pitix_write_inode,
};

static int __init pitix_init(void)
{
	int err;

	err = register_filesystem(&pitix_fs_type);
	if (err) {
		printk(LOG_LEVEL "register_filesystem failed\n");
		return err;
	}
	return 0;
}

static void __exit pitix_exit(void)
{
	unregister_filesystem(&pitix_fs_type);
}

module_init(pitix_init);
module_exit(pitix_exit);
