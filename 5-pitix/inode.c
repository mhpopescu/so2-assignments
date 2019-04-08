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

#define LOG_LEVEL	KERN_ALERT
#define PITIX_SUPER_BLOCK	0
#define PITIX_ROOT_INODE	0

/* declarations of functions that are part of operation structures */

// static int pitix_readdir(struct file *filp, struct dir_context *ctx);
static struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags);
// static int pitix_create(struct inode *dir, struct dentry *dentry,
		// umode_t mode, bool excl);

/* dir and inode operation structures */

struct inode_operations pitix_dir_inode_operations = {
	.lookup		= pitix_lookup,
	/* TODO 7/1: Use pitix_create as the create function. */
	// .create		= pitix_create,
};

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




struct inode *pitix_iget(struct super_block *sb, unsigned long ino)
{
	struct pitix_inode *pi;
	struct buffer_head *bh;
	struct inode *inode;
	// struct pitix_inode_info *pii;
	struct pitix_super_block *psb = pitix_sb(sb);
	int block_id;
	int inodes_per_block = pitix_inodes_per_block(sb);

	if (ino > get_inodes(sb)) {
		printk(LOG_LEVEL "Bad inode number on dev %s: %ld is out of range\n",
		       sb->s_id, (long)ino);
		return NULL;
	}

	block_id = psb->izone_block + ino / inodes_per_block;

	/* Allocate VFS inode. */
	inode = iget_locked(sb, ino);
	if (inode == NULL) {
		printk(LOG_LEVEL "error aquiring inode\n");
		return ERR_PTR(-ENOMEM);
	}

	if (!(bh = sb_bread(sb, block_id)))
		goto out_bad_sb;

	pi = ((struct pitix_inode *) bh->b_data) + ino % inodes_per_block;

	/* Fill VFS inode */
	inode->i_mode = pi->mode;
	i_uid_write(inode, pi->uid);
	i_gid_write(inode, pi->gid);
	inode->i_size = pi->size;
	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

	inode->i_mapping->a_ops = &pitix_aops;

	if (S_ISDIR(inode->i_mode)) {
		// inode->i_op = &simple_dir_inode_operations;
		// inode->i_fop = &simple_dir_operations;

		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
		inc_nlink(inode);
	}

	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
	}

	// pii = container_of(inode, struct pitix_inode_info, vfs_inode);
	// FIXME
	// pii->data_block = pi->direct_data_blocks[0];

	brelse(bh);
	unlock_new_inode(inode);

	return inode;

out_bad_sb:
	iget_failed(inode);
	return NULL;
}

static struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	/* TODO 6/1: Comment line. */
	//
	return simple_lookup(dir, dentry, flags);

	// struct super_block *sb = dir->i_sb;
	// struct pitix_dir_entry *de;
	// struct buffer_head *bh = NULL;
	// struct inode *inode = NULL;

	// dentry->d_op = sb->s_root->d_op;

	// de = pitix_find_entry(dentry, &bh);
	// if (de != NULL) {
	// 	printk(KERN_DEBUG "getting entry: name: %s, ino: %d\n",
	// 		de->name, de->ino);
	// 	inode = pitix_iget(sb, de->ino);
	// 	if (IS_ERR(inode))
	// 		return ERR_CAST(inode);
	// }

	// d_add(dentry, inode);
	// brelse(bh);

	// printk(KERN_DEBUG "looked up dentry %s\n", dentry->d_name.name);

	// return NULL;
}

static void pitix_put_super(struct super_block *sb)
{
	struct pitix_super_block *psb = pitix_sb(sb);

	/* Free superblock buffer head. */
	mark_buffer_dirty(psb->sb_bh);
	brelse(psb->sb_bh);

	printk(KERN_DEBUG "released superblock resources\n");
}

struct super_operations pitix_sops = {
	.statfs		= simple_statfs,
	.put_super	= pitix_put_super,
	/* TODO 4/2: add alloc and destroy inode functions */
	// .alloc_inode	= pitix_alloc_inode,
	// .destroy_inode	= pitix_destroy_inode,
	/* TODO 7/1:	= set write_inode function. */
	// .write_inode	= pitix_write_inode,
};

int pitix_fill_super(struct super_block *sb, void *data, int silent)
{
	struct pitix_super_block *psb;
	struct inode *root_inode;
	struct dentry *root_dentry;
	struct buffer_head *bh;
	int ret = -EINVAL;
pr_info("start\n");
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
