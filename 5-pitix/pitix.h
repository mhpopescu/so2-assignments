// SPDX-License-Identifier: GPL-2.0

#ifndef _PITIX_H
#define _PITIX_H

#define PITIX_MAGIC			0x58495450 /* ascii little endian for PTIX */
#define IZONE_BLOCKS		32
#define INODE_DIRECT_DATA_BLOCKS 5
#define PITIX_NAME_LEN		16

#define LOG_LEVEL			KERN_ALERT

/*
 *	filesystem layout:
 *
 *		SB		IMAP		DMAP		IZONE		DATA
 *	^		^ (1 block)  (1 block)  (32 blocks)
 *	|		|
 *	+-0		+-- 4096
 */

/*
 * PITIX super block on disk
 * Reused for in-memory super block
 */
struct pitix_super_block {
	unsigned long magic;
	__u8 version;
	__u8 block_size_bits;	/* block size = 2^block_size_bits */
	__u8 imap_block;		/* inode vector map block number */
	__u8 dmap_block;		/* data vector map block number */
	__u8 izone_block;		/* first inode block number */
	__u8 dzone_block;		/* first data block number */
	__u16 bfree;			/* number of free data blocks */
	__u16 ffree;			/* number of free inodes */
#ifdef __KERNEL__
	struct buffer_head *sb_bh, *dmap_bh, *imap_bh;
	__u8 *dmap, *imap;		/* data and inode vector map */
#endif
};

/* PITIX dir entry on disk */
struct pitix_dir_entry {
	__u32 ino;
	char name[PITIX_NAME_LEN];
};

/* PITIX inode on disk */
struct pitix_inode {
	__u32 mode;
	uid_t uid;
	gid_t gid;
	__u32 size;
	__u32 time;
	__u16 direct_data_blocks[INODE_DIRECT_DATA_BLOCKS];
	__u16 indirect_data_block;
};

/*
 * PITIX inode in memory
 */
struct pitix_inode_info {
	__u16 direct_db[INODE_DIRECT_DATA_BLOCKS];
	__u16 indirect_db;
	struct inode vfs_inode;
};

#ifdef __KERNEL__

/* returns size of PITIX inode on disk */
static inline int inode_size(void)
{
	return sizeof(struct pitix_inode);
}

/* returns size of PITIX dir entry on disk */
static inline int dir_entry_size(void)
{
	return sizeof(struct pitix_dir_entry);
}

/* returns number of PITIX dir entries per block */
static inline int dir_entries_per_block(struct super_block *sb)
{
	return sb->s_blocksize/dir_entry_size();
}

/* returns number of data blocks on disk */
static inline long get_blocks(struct super_block *sb)
{
	return 8*sb->s_blocksize;
}

/* returns number of PITIX inodes on disk */
static inline long get_inodes(struct super_block *sb)
{
	return IZONE_BLOCKS*sb->s_blocksize/inode_size();
}

static inline long pitix_inodes_per_block(struct super_block *sb)
{
	return sb->s_blocksize / inode_size();
}

/* Bitmap operations */
extern int pitix_alloc_inode(struct super_block *sb);
extern void pitix_free_inode(struct super_block *sb, int ino);
extern int pitix_alloc_block(struct super_block *sb);
extern void pitix_free_block(struct super_block *sb, int block);
extern int pitix_get_block(struct inode *inode, sector_t block,
		struct buffer_head *bh_result, int create);
extern const struct address_space_operations pitix_aops;

/* Dir operations */
extern const struct inode_operations pitix_dir_inode_operations;
extern const struct file_operations pitix_dir_operations;
ino_t pitix_inode_by_name(struct dentry *dentry, int delete);

/* File operations */
extern const struct file_operations pitix_file_operations;
extern const struct inode_operations pitix_file_inode_operations;
extern int pitix_getattr(const struct path *path, struct kstat *stat,
		u32 request_mask, unsigned int flags);
void pitix_truncate(struct inode *inode);

/* Inode operations */
extern struct inode *pitix_new_inode(struct super_block *sb);
extern int pitix_write_inode(struct inode *inode,
		struct writeback_control *wbc);
extern void pitix_evict_inode(struct inode *inode);

extern struct inode *pitix_iget(struct super_block *sb, unsigned long ino);

/* Super operations */
extern int pitix_fill_super(struct super_block *sb, void *data, int silent);
extern const struct super_operations pitix_sops;

/* Other functions */
int pitix_make_empty(struct inode *inode, struct inode *dir);
int pitix_empty_dir(struct inode *inode);
int pitix_add_link(struct dentry *dentry, struct inode *inode);
int pitix_delete_entry(struct pitix_dir_entry *de, struct page *page);
int count_blocks(struct inode *inode);
void pitix_set_inode(struct inode *inode, dev_t rdev);
struct pitix_dir_entry *pitix_find_entry(struct dentry *dentry,
		struct page **res_page);

#endif

static inline struct pitix_super_block *pitix_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct pitix_inode_info *pitix_i(struct inode *inode)
{
	return container_of(inode, struct pitix_inode_info, vfs_inode);
}

#endif
