/*
 * linux/fs/ecfs/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include <linux/fs_ecfs.h>
#include <linux/ecfs_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>


int ecfs_ioctl (struct inode * inode, struct file * filp, unsigned int cmd,
		unsigned long arg)
{
	unsigned int flags;

	ecfs_debug ("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case ECFS_IOC_GETFLAGS:
		flags = inode->u.ecfs_i.i_flags & ECFS_FL_USER_VISIBLE;
		return put_user(flags, (int *) arg);
	case ECFS_IOC_SETFLAGS: {
		unsigned int oldflags;

		if (IS_RDONLY(inode))
			return -EROFS;

		if ((current->fsuid != inode->i_uid) && !capable(CAP_FOWNER))
			return -EPERM;

		if (get_user(flags, (int *) arg))
			return -EFAULT;

		oldflags = inode->u.ecfs_i.i_flags;

		/*
		 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
		 * the relevant capability.
		 *
		 * This test looks nicer. Thanks to Pauline Middelink
		 */
		if ((flags ^ oldflags) & (ECFS_APPEND_FL | ECFS_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE))
				return -EPERM;
		}

		flags = flags & ECFS_FL_USER_MODIFIABLE;
		flags |= oldflags & ~ECFS_FL_USER_MODIFIABLE;
		inode->u.ecfs_i.i_flags = flags;

		if (flags & ECFS_SYNC_FL)
			inode->i_flags |= S_SYNC;
		else
			inode->i_flags &= ~S_SYNC;
		if (flags & ECFS_APPEND_FL)
			inode->i_flags |= S_APPEND;
		else
			inode->i_flags &= ~S_APPEND;
		if (flags & ECFS_IMMUTABLE_FL)
			inode->i_flags |= S_IMMUTABLE;
		else
			inode->i_flags &= ~S_IMMUTABLE;
		if (flags & ECFS_NOATIME_FL)
			inode->i_flags |= S_NOATIME;
		else
			inode->i_flags &= ~S_NOATIME;
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
		return 0;
	}
	case ECFS_IOC_GETVERSION:
		return put_user(inode->i_generation, (int *) arg);
	case ECFS_IOC_SETVERSION:
		if ((current->fsuid != inode->i_uid) && !capable(CAP_FOWNER))
			return -EPERM;
		if (IS_RDONLY(inode))
			return -EROFS;
		if (get_user(inode->i_generation, (int *) arg))
			return -EFAULT;	
		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty(inode);
		return 0;
	default:
		return -ENOTTY;
	}
}
