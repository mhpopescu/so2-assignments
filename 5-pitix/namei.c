// SPDX-License-Identifier: GPL-2.0
/*
 *  namei.c
 *
 *  INSPIRED FROM linux/fs/minix/namei.c
 *
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

static struct dentry *pitix_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
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

void pitix_set_inode(struct inode *inode, dev_t rdev)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &pitix_file_inode_operations;
		inode->i_fop = &pitix_file_operations;
		inode->i_mapping->a_ops = &pitix_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &pitix_dir_inode_operations;
		inode->i_fop = &pitix_dir_operations;
		inode->i_mapping->a_ops = &pitix_aops;
	} 
	/*else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &minix_symlink_inode_operations;
		inode_nohighmem(inode);
		inode->i_mapping->a_ops = &minix_aops;
	} else
		init_special_inode(inode, inode->i_mode, rdev);
	*/
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

static int pitix_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	int error;
	struct inode *inode;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = pitix_new_inode(dir, mode, &error);

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

static int pitix_link(struct dentry *old_dentry, struct inode * dir,
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

	inode = pitix_new_inode(dir, S_IFDIR | mode, &err);
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

struct inode_operations pitix_dir_inode_operations = {
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
