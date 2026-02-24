/*
 *  linux/fs/ecfs/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ecfs fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 * 	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/fs_ecfs.h>
#include <linux/ecfs_fs.h>
#include "rc4.h"
#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <linux/malloc.h>

static loff_t ecfs_file_lseek(struct file *, loff_t, int);
static int ecfs_open_file (struct inode *, struct file *);

#define ECFS_MAX_SIZE(bits)							\
	(((ECFS_NDIR_BLOCKS + (1LL << (bits - 2)) + 				\
	   (1LL << (bits - 2)) * (1LL << (bits - 2)) + 				\
	   (1LL << (bits - 2)) * (1LL << (bits - 2)) * (1LL << (bits - 2))) * 	\
	  (1LL << bits)) - 1)

static long long ecfs_max_sizes[] = {
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
ECFS_MAX_SIZE(10), ECFS_MAX_SIZE(11), ECFS_MAX_SIZE(12), ECFS_MAX_SIZE(13)
};

/*
 * Make sure the offset never goes beyond the 32-bit mark..
 */
static loff_t ecfs_file_lseek(
	struct file *file,
	loff_t offset,
	int origin)
{
	struct inode *inode = file->f_dentry->d_inode;

	switch (origin) {
		case 2:
			offset += inode->i_size;
			break;
		case 1:
			offset += file->f_pos;
	}
	if (offset<0)
		return -EINVAL;
	if (((unsigned long long) offset >> 32) != 0) {
		if (offset > ecfs_max_sizes[ECFS_BLOCK_SIZE_BITS(inode->i_sb)])
			return -EINVAL;
	} 
	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_reada = 0;
		file->f_version = ++event;
	}
	return offset;
}

/*
 * Called when an inode is released. Note that this is different
 * from ecfs_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ecfs_release_file (struct inode * inode, struct file * filp)
{
	if (filp->f_mode & FMODE_WRITE)
		ecfs_discard_prealloc (inode);
	return 0;
}

/*
 * Called when an inode is about to be open.
 * We use this to disallow opening RW large files on 32bit systems if
 * the caller didn't specify O_LARGEFILE.  On 64bit systems we force
 * on this flag in sys_open.
 */
static int ecfs_open_file (struct inode * inode, struct file * filp)
{
	if (!(filp->f_flags & O_LARGEFILE) &&
	    inode->i_size > 0x7FFFFFFFLL)
		return -EFBIG;
	return 0;
}


unsigned char *ecfs_key = "A";

/* page flags 21 .. 29 are unused
#define PAGE_PLAIN 22

struct page * ecfs_filemap_nopage(struct vm_area_struct *area,
        unsigned long address, int no_share)
{
	unsigned int from = area->vm_file->f_pos;
	unsigned char *ptr;
	unsigned int count = area->vm_end - area->vm_start;
	struct page *r;
	rc4_key rc4key;

	if (!orig_ops)
		return NULL;

	printk("<1> foo\n");	
	r = orig_ops->nopage(area, address, no_share);

	printk("<1> bar %p %d %d\n", r->virtual, from, r->count);

	ptr = r->virtual;

	if (!ptr)// || test_bit(PAGE_PLAIN, &r->flags))
		return r;

	prepare_key(ecfs_key, strlen(ecfs_key), &rc4key);
	rc4(ptr, PAGE_SIZE, &rc4key, from);

	SetPageReserved(r);
	return r;
}


static struct vm_operations_struct ecfs_nopage = {
        nopage:         ecfs_filemap_nopage,
};



int ecfs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int r = generic_file_mmap(file, vma);
	orig_ops = vma->vm_ops;
	vma->vm_ops = &ecfs_nopage;
	return r;	
}


*/
ssize_t ecfs_file_read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	rc4_key rc4key;
	unsigned int from = file->f_pos;
	unsigned char *ptr;
	ssize_t r;
	char file_key[1024+100];	/* to avoid keystream-reuse */

	memset(file_key, 0, sizeof(file_key));

	/* Should not overflow as init() checked for > 1024 */
	sprintf(file_key, "%s%lx", ecfs_key, file->f_dentry->d_inode->i_ino);

	r = generic_file_read(file, buf, count, ppos);
	if (r < 0)
		return r;

	if ((ptr = kmalloc(count, GFP_KERNEL)) == NULL)
		return r;

	copy_from_user(ptr, buf, r);
	
	prepare_key(file_key, strlen(file_key), &rc4key);
	rc4(ptr, r, &rc4key, from);

	copy_to_user(buf, ptr, r);
	kfree(ptr);
	return r;
}


ssize_t
ecfs_file_write(struct file *file, const char *buf, size_t count, loff_t *ppos)
{
	rc4_key rc4key;
	unsigned int from = file->f_pos;
	unsigned char *ptr;
	mm_segment_t orig_fs;
	ssize_t r;
	char file_key[1024+100];	/* to avoid keystream-reuse */

	memset(file_key, 0, sizeof(file_key));

	/* Should not overflow as init() checked for > 1024 */
	sprintf(file_key, "%s%lx", ecfs_key, file->f_dentry->d_inode->i_ino);


	if ((ptr = kmalloc(count, GFP_KERNEL)) == NULL)
		return -1;

	copy_from_user(ptr, buf, count);

	prepare_key(file_key, strlen(file_key), &rc4key);
	rc4(ptr, count, &rc4key, from);

	orig_fs = get_fs();
	set_fs(KERNEL_DS);
	r = generic_file_write(file, ptr, count, ppos);
	set_fs(orig_fs);
	kfree(ptr);
	return r;
}


/*
 * We have mostly NULL's here: the current defaults are ok for
 * the ecfs filesystem.
 */
struct file_operations ecfs_file_operations = {
	llseek:		ecfs_file_lseek,
	read:		ecfs_file_read,
	write:		ecfs_file_write,
	ioctl:		ecfs_ioctl,
	mmap:		generic_file_mmap,
	open:		ecfs_open_file,
	release:	ecfs_release_file,
	fsync:		ecfs_sync_file,
};

struct inode_operations ecfs_file_inode_operations = {
	truncate:	ecfs_truncate,
};
