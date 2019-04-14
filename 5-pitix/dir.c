// SPDX-License-Identifier: GPL-2.0
/*
 *  dir.c
 *
 *  pitix directory handling functions
 *  INSPIRED FROM linux/fs/minix/dir.c
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

static inline void dir_put_page(struct page *page)
{
	kunmap(page);
	put_page(page);
}

static struct page *dir_get_page(struct inode *dir)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, 0, NULL);

	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static inline void *pitix_next_entry(void *de)
{
	return (void *)((char *)de + dir_entry_size());
}

int pitix_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct pitix_super_block *psb = pitix_sb(sb);
	unsigned int chunk_size = dir_entry_size();
	unsigned long pos = ctx->pos;
	char *kaddr;
	struct page *page = dir_get_page(inode);
	struct pitix_dir_entry *de;
	int over;

	if (pos >= inode->i_size)
		return 0;

	if (IS_ERR(page))
		return -EINVAL;

	kaddr = (char *)page_address(page);
	for (; ctx->pos < dir_entries_per_block(sb); ctx->pos++) {
		de = (struct pitix_dir_entry *)kaddr + ctx->pos;
		if (de->ino) {
			over = dir_emit(ctx, de->name, PITIX_NAME_LEN,
					de->ino, DT_UNKNOWN);
			if (over) {
				ctx->pos += 1;
				break;
			}
		}
	}

	dir_put_page(page);
	return 0;
}

static inline int namecompare(int len, int maxlen,
	const char *name, const char *buffer)
{
	if (len < maxlen && buffer[len])
		return 0;
	return !memcmp(name, buffer, len);
}

/*
 *	pitix_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the cache buffer in which the entry was found, and the entry
 * itself (as a parameter - res_dir). It does NOT read the inode of the
 * entry - you'll have to do that yourself if you want to.
 */
struct pitix_dir_entry *pitix_find_entry(struct dentry *dentry,
		struct page **res_page)
{
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct inode *dir = d_inode(dentry->d_parent);
	struct super_block *sb = dir->i_sb;
	struct page *page = NULL;
	char *kaddr;
	int p;
	struct pitix_dir_entry *de;

	*res_page = NULL;

	page = dir_get_page(dir);
	if (IS_ERR(page))
		return NULL;

	kaddr = (char *)page_address(page);
	for (p = 0; p < dir_entries_per_block(sb); p++) {
		de = (struct pitix_dir_entry *)kaddr + p;

		if (!de->ino)
			continue;
		if (namecompare(namelen, PITIX_NAME_LEN, name, de->name))
			goto found;
	}
	dir_put_page(page);

	return NULL;

found:
	*res_page = page;
	return de;
}

ino_t pitix_inode_by_name(struct dentry *dentry, int delete)
{
	struct page *page;
	struct pitix_dir_entry *de = pitix_find_entry(dentry, &page);
	ino_t res = 0;

	if (de) {
		struct address_space *mapping = page->mapping;
		struct inode *inode = mapping->host;

		res = de->ino;
		dir_put_page(page);
	}
	return res;
}

static int pitix_prepare_chunk(struct page *page, loff_t pos, unsigned int len)
{
	return __block_write_begin(page, pos, len, pitix_get_block);
}

static int dir_commit_chunk(struct page *page, loff_t pos, unsigned int len)
{
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;

	block_write_end(NULL, mapping, pos, len, len, page, NULL);

	if (pos+len > dir->i_size) {
		i_size_write(dir, pos+len);
		mark_inode_dirty(dir);
	}
	if (IS_DIRSYNC(dir))
		err = write_one_page(page);
	else
		unlock_page(page);

	return err;
}

int pitix_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = d_inode(dentry->d_parent);
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct super_block *sb = dir->i_sb;
	struct pitix_dir_entry *de;
	struct page *page = NULL;
	char *kaddr;
	int p, err;
	char *namx = NULL;
	__u16 inumber;

	page = dir_get_page(dir);
	err = PTR_ERR(page);
	if (IS_ERR(page))
		goto out;

	lock_page(page);
	kaddr = (char *)page_address(page);

	for (p = 0; p < dir_entries_per_block(sb); p++) {
		de = (struct pitix_dir_entry *)kaddr + p;
		namx = de->name;
		inumber = de->ino;

		if (!inumber)
			goto got_it;
		err = -EEXIST;
		if (namecompare(namelen, PITIX_NAME_LEN, name, namx))
			goto out_unlock;
	}

	err = -ENOMEM;
	goto out_unlock;

got_it:
	err = pitix_prepare_chunk(page, p * dir_entry_size(), dir_entry_size());
	if (err)
		goto out_unlock;
	memcpy(namx, name, namelen);
	memset(namx + namelen, 0, dir_entry_size() - namelen - 4);
	de->ino = inode->i_ino;

	err = dir_commit_chunk(page, p * dir_entry_size(), dir_entry_size());
	dir->i_mtime = dir->i_ctime = current_time(dir);
	mark_inode_dirty(dir);
out_put:
	dir_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

int pitix_delete_entry(struct pitix_dir_entry *de, struct page *page)
{
	struct inode *inode = page->mapping->host;
	char *kaddr = page_address(page);
	loff_t pos = (char *)de - kaddr;
	unsigned int len = dir_entry_size();
	int err;

	lock_page(page);
	err = pitix_prepare_chunk(page, pos, len);
	if (err == 0) {
		de->ino = 0;
		err = dir_commit_chunk(page, pos, len);
	} else
		unlock_page(page);
	dir_put_page(page);
	inode->i_ctime = inode->i_mtime = current_time(inode);
	mark_inode_dirty(inode);

	return err;
}

int pitix_make_empty(struct inode *inode, struct inode *dir)
{
	struct page *page = grab_cache_page(inode->i_mapping, 0);
	char *kaddr;
	int err = 0;
	struct pitix_dir_entry *de;
	struct super_block *sb = dir->i_sb;

	if (!page)
		return -ENOMEM;
	err = pitix_prepare_chunk(page, 0, sb->s_blocksize);
	if (err) {
		unlock_page(page);
		goto fail;
	}

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, sb->s_blocksize);
	kunmap_atomic(kaddr);

	err = dir_commit_chunk(page, 0, sb->s_blocksize);
fail:
	put_page(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int pitix_empty_dir(struct inode *inode)
{
	struct page *page = NULL;
	unsigned long i, npages = dir_pages(inode);
	struct super_block *sb = inode->i_sb;
	char *p, *kaddr, *limit;

	page = dir_get_page(inode);
	if (IS_ERR(page))
		BUG();

	kaddr = (char *)page_address(page);
	limit = kaddr + sb->s_blocksize - dir_entry_size();
	for (p = kaddr; p <= limit; p = pitix_next_entry(p)) {
		struct pitix_dir_entry *de = (struct pitix_dir_entry *)p;

		if (de->ino != 0)
			goto not_empty;
	}

	dir_put_page(page);
	return 1;

not_empty:
	dir_put_page(page);
	return 0;
}

const struct file_operations pitix_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= pitix_readdir,
	.fsync		= generic_file_fsync,
};
