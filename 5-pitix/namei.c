// SPDX-License-Identifier: GPL-2.0

/*
 * namei.c - pitix inode directory handling functions
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

/*
 * Create a new inode
 */
static struct inode *pitix_create_inode(const struct inode *dir, umode_t mode,
		int *error)
{
	struct inode *inode = NULL;
	int ino = 0;
	int i = 0;

	struct super_block *sb = dir->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);

	/* Get free inode number from bitmap*/
	ino = pitix_alloc_inode(sb);
	if (!ino) {
		*error = -ENOSPC;
		goto out_create_inode;
	}

	/* Alloc memory for a new inode*/
	inode = new_inode(sb);
	if (!inode) {
		pitix_free_inode(sb, ino);
		*error = -ENOMEM;
		goto out_create_inode;
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

out_create_inode:
	return NULL;
}

/*
 * pitix_dir_inode_operation
 * Search for an entry in directory
 */
static struct dentry *pitix_lookup(struct inode *dir,
		struct dentry *dentry, unsigned int flags)
{
	ino_t ino = 0;
	struct inode *inode = NULL;

	if (dentry->d_name.len > PITIX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	ino = pitix_inode_by_name(dentry, 0);
	if (ino)
		inode = pitix_iget(dir->i_sb, ino);

	return d_splice_alias(inode, dentry);
}

/*
 * Add entry in directory
 */
static int add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = pitix_add_link(dentry, inode);

	if (!err) {
		d_instantiate(dentry, inode);
		goto out_nondir;
	}

	inode_dec_link_count(inode);
	iput(inode);

out_nondir:
	return err;
}

/*
 * Create a new entry
 */
static int pitix_mknod(struct inode *dir,
		struct dentry *dentry, umode_t mode, dev_t rdev)
{
	int error = 0;
	struct inode *inode = NULL;

	if (!old_valid_dev(rdev)) {
		error = -EINVAL;
		goto out_mknod;
	}

	inode = pitix_create_inode(dir, mode, &error);
	if (inode) {
		inode_init_owner(inode, dir, mode);
		pitix_set_inode(inode, rdev);
		mark_inode_dirty(inode);
		error = add_nondir(dentry, inode);
	}

out_mknod:
	return error;
}

/*
 * pitix_dir_inode_operation
 */
static int pitix_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return pitix_mknod(dir, dentry, mode, 0);
}

/*
 * pitix_dir_inode_operation
 */
static int pitix_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *inode = d_inode(old_dentry);

	inode->i_ctime = current_time(inode);
	inode_inc_link_count(inode);
	ihold(inode);

	return add_nondir(dentry, inode);
}

/*
 * pitix_dir_inode_operation
 * Create an empty directory
 */
static int pitix_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = NULL;
	int err = 0;

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

/*
 * pitix_dir_inode_operation
 * remove file/directory
 */
static int pitix_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = -ENOENT;
	struct page *page = NULL;
	struct pitix_dir_entry *de = NULL;

	struct inode *inode = d_inode(dentry);

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

/*
 * pitix_dir_inode_operation
 * remove empty directory
 */
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

/*
 * Directories can handle most operations...
 */
const struct inode_operations pitix_dir_inode_operations = {
	.lookup		= pitix_lookup,
	.create		= pitix_create,
	.link		= pitix_link,
	.unlink		= pitix_unlink,
	.mkdir		= pitix_mkdir,
	.rmdir		= pitix_rmdir,
	.getattr	= pitix_getattr,
	.mknod		= pitix_mknod,
};
