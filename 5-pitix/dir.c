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

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
pitix_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = PAGE_SIZE;

	if (page_nr == (inode->i_size >> PAGE_SHIFT))
		last_byte = inode->i_size & (PAGE_SIZE - 1);
	return last_byte;
}

static struct page *dir_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page))
		kmap(page);
	return page;
}

static inline void *pitix_next_entry(void *de)
{
	return (void*)((char*)de + dir_entry_size());
}

// int pitix_readdir(struct file *file, struct dir_context *ctx)
// {
// 	struct inode *inode = file_inode(file);
// 	struct super_block *sb = inode->i_sb;
// 	unsigned chunk_size = dir_entry_size();
// 	unsigned long npages = dir_pages(inode);
// 	unsigned long pos = ctx->pos;
// 	unsigned offset;
// 	unsigned long n;

// 	ctx->pos = pos = ALIGN(pos, chunk_size);
// 	if (pos >= inode->i_size)
// 		return 0;

// 	offset = pos & ~PAGE_MASK;
// 	n = pos >> PAGE_SHIFT;

// 	// pr_info("folder %s offset %d npages %ld n %ld dir_entry_size %d\n", file->f_path.dentry->d_name.name,
// 	// 	offset, npages, n, dir_entry_size());
// 	// struct pitix_super_block *psb = pitix_sb(sb);
// 	// pr_info("%d imap %d dzone\n", psb->imap_block, psb->dzone_block);
// 	// pr_info("%d %d\n", psb->imap[0], psb->dmap[0]);

// 	for ( ; n < npages; n++, offset = 0) {
// 		char *p, *kaddr, *limit;
// 		struct page *page = dir_get_page(inode, n);

// 		if (IS_ERR(page))
// 			continue;
// 		kaddr = (char *)page_address(page);
// 		p = kaddr+offset;

// 		limit = kaddr + pitix_last_byte(inode, n) - chunk_size;
// 		for ( ; p <= limit; p = pitix_next_entry(p)) {
// 			const char *name;
// 			struct pitix_dir_entry *de = (struct pitix_dir_entry *)p;
// 			name = de->name;
			
// 			// pr_info("FOR %d ino %d name %s", p, de->ino, name);
// 			if (de->ino) {
// 				unsigned l = strnlen(name, PITIX_NAME_LEN);
// 				if (!dir_emit(ctx, name, l,
// 					      de->ino, DT_UNKNOWN)) {
// 					dir_put_page(page);
// 					return 0;
// 				}
// 			}
// 			ctx->pos += chunk_size;
// 		}
// 		pr_info("\n");
// 		dir_put_page(page);
// 	}
	
// 	return 0;
// }


int pitix_readdir(struct file *file, struct dir_context *ctx)
{
	struct buffer_head *bh = NULL;
	struct pitix_dir_entry *de;
	struct inode *inode = file_inode(file);
	struct pitix_inode_info *pii = pitix_i(inode);
	struct super_block *sb = inode->i_sb;
	int err = 0;
	int over;

	/* read data block for directory inode */
	bh = sb_bread(sb, pitix_sb(sb)->dzone_block + pii->dd_blocks[0]);
	if (bh == NULL) {
		printk(LOG_LEVEL "could not read block\n");
		err = -ENOMEM;
		goto out_bad_sb;
	}
	// printk("Read data block %d for folder %s\n", pii->dd_blocks[0],
	// 		file->f_path.dentry->d_name.name);

	
	for (; ctx->pos < dir_entries_per_block(sb); ctx->pos++) {
		de = (struct pitix_dir_entry *) bh->b_data + ctx->pos;
		if (de->ino != 0) {
			over = dir_emit(ctx, de->name, PITIX_NAME_LEN,
					de->ino, DT_UNKNOWN);
			if (over) {
				// printk(LOG_LEVEL "Read %s from folder %s, ctx->pos: %lld\n",
				// 		de->name,
				// 		file->f_path.dentry->d_name.name,
				// 		ctx->pos);
				ctx->pos += 1;
				goto done;
			}
		}
	}

done:
	brelse(bh);
out_bad_sb:
	return err;
}

static inline int namecompare(int len, int maxlen,
	const char * name, const char * buffer)
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
struct pitix_dir_entry *pitix_find_entry(struct dentry *dentry, struct page **res_page)
{
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct inode *dir = d_inode(dentry->d_parent);
	struct super_block *sb = dir->i_sb;
	unsigned long n;
	unsigned long npages = dir_pages(dir);
	struct page *page = NULL;
	char *p;

	char *namx;
	__u32 ino;
	*res_page = NULL;

	for (n = 0; n < npages; n++) {
		char *kaddr, *limit;

		page = dir_get_page(dir, n);
		if (IS_ERR(page))
			continue;

		kaddr = (char*)page_address(page);
		limit = kaddr + pitix_last_byte(dir, n) - dir_entry_size();
		for (p = kaddr; p <= limit; p = pitix_next_entry(p)) {
			struct pitix_dir_entry *de = (struct pitix_dir_entry *)p;
			namx = de->name;
			ino = de->ino;

			if (!ino)
				continue;
			if (namecompare(namelen, PITIX_NAME_LEN, name, namx))
				goto found;
		}
		dir_put_page(page);
	}
	return NULL;

found:
	*res_page = page;
	return (struct pitix_dir_entry *)p;
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

static int pitix_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, pitix_get_block);
}

static int dir_commit_chunk(struct page *page, loff_t pos, unsigned len)
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
	struct page *page = NULL;
	unsigned long npages = dir_pages(dir);
	unsigned long n;
	char *kaddr, *p;
	struct pitix_dir_entry *de;
	loff_t pos;
	int err;
	char *namx = NULL;
	__u32 inumber;

	/*
	 * We take care of directory expansion in the same loop
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *limit, *dir_end;

		page = dir_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = (char*)page_address(page);
		dir_end = kaddr + pitix_last_byte(dir, n);
		limit = kaddr + PAGE_SIZE - dir_entry_size();
		for (p = kaddr; p <= limit; p = pitix_next_entry(p)) {
			de = (struct pitix_dir_entry *)p;
			namx = de->name;
			inumber = de->ino;

			if (p == dir_end) {
				/* We hit i_size */
				de->ino = 0;
				goto got_it;
			}
			if (!inumber)
				goto got_it;
			err = -EEXIST;
			if (namecompare(namelen, PITIX_NAME_LEN, name, namx))
				goto out_unlock;
		}
		unlock_page(page);
		dir_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = page_offset(page) + p - (char *)page_address(page);
	err = pitix_prepare_chunk(page, pos, dir_entry_size());
	if (err)
		goto out_unlock;
	memcpy (namx, name, namelen);
	memset (namx + namelen, 0, dir_entry_size() - namelen - 4);
	de->ino = inode->i_ino;

	err = dir_commit_chunk(page, pos, dir_entry_size());
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
	loff_t pos = page_offset(page) + (char*)de - kaddr;
	unsigned len = dir_entry_size();
	int err;

	lock_page(page);
	err = pitix_prepare_chunk(page, pos, len);
	if (err == 0) {
		de->ino = 0;
		err = dir_commit_chunk(page, pos, len);
	} else {
		unlock_page(page);
	}

	dir_put_page(page);
	inode->i_ctime = inode->i_mtime = current_time(inode);
	mark_inode_dirty(inode);
	return err;
}

int pitix_make_empty(struct inode *inode, struct inode *dir)
{
	struct page *page = grab_cache_page(inode->i_mapping, 0);
	char *kaddr;
	int err;
	struct pitix_dir_entry *de;

	if (!page)
		return -ENOMEM;
	err = pitix_prepare_chunk(page, 0, 2 * dir_entry_size());
	if (err) {
		unlock_page(page);
		goto fail;
	}

	kaddr = kmap_atomic(page);
	memset(kaddr, 0, PAGE_SIZE);

	de = (struct pitix_dir_entry *)kaddr;
	de->ino = inode->i_ino;
	strcpy(de->name, ".");
	de = pitix_next_entry(de);
	de->ino = dir->i_ino;
	strcpy(de->name, "..");
	kunmap_atomic(kaddr);

	err = dir_commit_chunk(page, 0, 2 * dir_entry_size());
fail:
	put_page(page);
	return err;
}

struct file_operations pitix_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= pitix_readdir,
};
