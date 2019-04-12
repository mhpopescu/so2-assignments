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
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/vfs.h>

#include "pitix.h"

MODULE_DESCRIPTION("PITIX filesystem");
MODULE_AUTHOR("SO2");
MODULE_LICENSE("GPL");

#define PITIX_SUPER_BLOCK	0
#define PITIX_ROOT_INODE	0

static int pitix_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, pitix_get_block, wbc);
}

static void pitix_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		pitix_truncate(inode);
	}
}

static int pitix_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				pitix_get_block);
	if (unlikely(ret))
		pitix_write_failed(mapping, pos + len);

	return ret;
}

static sector_t pitix_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, pitix_get_block);
}

static int pitix_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, pitix_get_block);
}

static void pitix_destroy_inode(struct inode *inode)
{
	kfree(pitix_i(inode));
}

void pitix_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		pitix_truncate(inode);
	}
	invalidate_inode_buffers(inode);
	clear_inode(inode);

	if (!inode->i_nlink)
		pitix_free_inode(inode->i_sb, inode->i_ino);

}

struct inode *pitix_alloc_inode(struct super_block *s)
{
	struct pitix_inode_info *pii;

	pii = kzalloc(sizeof (struct pitix_inode_info), GFP_KERNEL);
	if (!pii)
		return NULL;
	inode_init_once(&pii->vfs_inode);

	return &pii->vfs_inode;
}



static int pitix_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = sb->s_magic;
	buf->f_bsize = sb->s_blocksize;
	// buf->f_blocks = (sbi->s_nzones - sbi->s_firstdatazone) << sbi->s_log_zone_size;
	buf->f_bfree = psb->bfree;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = get_blocks(sb);
	buf->f_ffree = psb->ffree;
	buf->f_namelen = PITIX_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
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

	pi = ((struct pitix_inode *) (*bh)->b_data);
	return pi + ino % pitix_inodes_per_block(sb);
}

static struct buffer_head *pitix_update_inode(struct inode *inode)
{
	struct buffer_head *bh;
	struct pitix_inode *raw_inode;
	struct pitix_inode_info *pi = pitix_i(inode);
	int i;

	raw_inode = pitix_raw_inode(inode->i_sb, inode->i_ino, &bh);
	if (!raw_inode)
		return NULL;
	raw_inode->mode = inode->i_mode;
	raw_inode->uid = fs_high2lowuid(i_uid_read(inode));
	raw_inode->gid = fs_high2lowgid(i_gid_read(inode));
	raw_inode->size = inode->i_size;
	raw_inode->time = inode->i_mtime.tv_sec;

	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; i++)
		raw_inode->direct_data_blocks[i] = pi->direct_db[i];
	raw_inode->indirect_data_block = pi->indirect_db;

	mark_buffer_dirty(bh);
	return bh;
}

/*
 * write VFS inode contents to disk
 */
int pitix_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err = 0;
	struct buffer_head *bh;

	bh = pitix_update_inode(inode);
	if (!bh)
		return -EIO;
	if (wbc->sync_mode == WB_SYNC_ALL && buffer_dirty(bh)) {
		sync_dirty_buffer(bh);
		if (buffer_req(bh) && !buffer_uptodate(bh)) {
			printk(LOG_LEVEL "IO error syncing minix inode [%s:%08lx]\n",
				inode->i_sb->s_id, inode->i_ino);
			err = -EIO;
		}
	}
	brelse (bh);
	return err;
}

int pitix_getattr(const struct path *path, struct kstat *stat,
		  u32 request_mask, unsigned int flags)
{
	struct super_block *sb = path->dentry->d_sb;
	struct inode *inode = d_inode(path->dentry);

	generic_fillattr(inode, stat);
	
	stat->blocks = get_blocks(sb);

	stat->blksize = sb->s_blocksize;
	return 0;
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
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	pitix_set_inode(inode, 0);

	pii = pitix_i(inode);
	for (i = 0; i < INODE_DIRECT_DATA_BLOCKS; ++i)
		pii->direct_db[i] = raw_inode->direct_data_blocks[i];
	pii->indirect_db = raw_inode->indirect_data_block;

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
pr_info("bits %d blockSZ %ld imap %d dmap %d izone %d dzone %d bfree %d ffree %d PAGE_SIZE %ld\n", 
		psb->block_size_bits, sb->s_blocksize, psb->imap_block, psb->dmap_block, 
		psb->izone_block, psb->dzone_block, psb->bfree, psb->ffree,
		PAGE_SIZE);
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
	.readpage       = pitix_readpage,
	.writepage 		= pitix_writepage,
	.write_begin 	= pitix_write_begin,
	.write_end  	= generic_write_end,
	.bmap 			= pitix_bmap,
};

struct file_operations pitix_file_operations = {
	.llseek		= generic_file_llseek,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};

struct inode_operations pitix_file_inode_operations = {
	.getattr	= pitix_getattr,
};

struct super_operations pitix_sops = {
	.alloc_inode	= pitix_alloc_inode,
	.destroy_inode	= pitix_destroy_inode,
	.write_inode	= pitix_write_inode,
	.evict_inode	= pitix_evict_inode,
	.statfs			= pitix_statfs,
	.put_super		= pitix_put_super,
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
