// SPDX-License-Identifier: GPL-2.0

/*
 * namei.c
 *
 * INSPIRED FROM linux/fs/minix/namei.c
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

static struct inode *pitix_create_inode(const struct inode *dir, umode_t mode, int *error)
{
	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	struct inode *inode;
	int ino;
	int i;

	ino = pitix_alloc_inode(sb);
	if (!ino){
		*error = -ENOSPC;
		return NULL;
	}

	inode = new_inode(sb);
	if (!inode) {
		pitix_free_inode(sb, ino);
		*error = -ENOMEM;
		return NULL;
	}

	inode_init_owner(inode, dir, mode);
	inode->i_ino = ino;
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

static struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = NULL;
	ino_t ino;

	if (dentry->d_name.len > PITIX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = pitix_inode_by_name(dentry, 0);
	if (ino)
		inode = pitix_iget(dir->i_sb, ino);

	return d_splice_alias(inode, dentry);
}

static int add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = pitix_add_link(dentry, inode);

	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);

	return err;
}

static int pitix_mknod(struct inode *dir,
		struct dentry *dentry, umode_t mode, dev_t rdev)
{
	int error;
	struct inode *inode;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = pitix_create_inode(dir, mode, &error);

	if (inode) {
		inode_init_owner(inode, dir, mode);
		pitix_set_inode(inode, rdev);
		mark_inode_dirty(inode);
		error = add_nondir(dentry, inode);
	}

	return error;
}

static int pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
						bool excl)
{
	return pitix_mknod(dir, dentry, mode, 0);
}

static int pitix_link(struct dentry *old_dentry, struct inode *dir,
						struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	return add_nondir(dentry, inode);
}

static int pitix_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	int err;

	inode_inc_link_count(dir);

	inode = pitix_create_inode(dir, S_IFDIR | mode, &err);
	if (!inode)
		goto out_dir;

	pitix_set_inode(inode, 0);
	inode_inc_link_count(inode);

	err = pitix_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = pitix_add_link(dentry, inode);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);

out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput(inode);
out_dir:
	inode_dec_link_count(dir);
	goto out;
}


static int pitix_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = -ENOENT;
	struct inode *inode = d_inode(dentry);
	struct page *page;
	struct pitix_dir_entry *de;

	de = pitix_find_entry(dentry, &page);
	if (!de)
		goto end_unlink;

	err = pitix_delete_entry(de, page);
	if (err)
		goto end_unlink;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);

end_unlink:
	return err;
}

static int pitix_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_inode(dentry);
	int err = -ENOTEMPTY;

	if (pitix_empty_dir(inode)) {
		err = pitix_unlink(dir, dentry);
		if (!err) {
			inode_dec_link_count(dir);
			inode_dec_link_count(inode);
		}
	}

	return err;
}

const struct inode_operations pitix_dir_inode_operations = {
	.lookup		= pitix_lookup,
	.create		= pitix_create,
	.link		= pitix_link,
	.unlink		= pitix_unlink,
	.mkdir		= pitix_mkdir,
	.rmdir		= pitix_rmdir,
	// .rename		= minix_rename,
	.getattr	= pitix_getattr,
	.mknod		= pitix_mknod,
};
