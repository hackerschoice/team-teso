/*
 *  linux/fs/ecfs/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs_ecfs.h>
#include <linux/ecfs_fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/locks.h>
#include <asm/uaccess.h>

#include <linux/blkdev.h>

extern unsigned char *ecfs_key;

static char error_buf[1024];

void ecfs_error (struct super_block * sb, const char * function,
		 const char * fmt, ...)
{
	va_list args;

	if (!(sb->s_flags & MS_RDONLY)) {
		sb->u.ecfs_sb.s_mount_state |= ECFS_ERROR_FS;
		sb->u.ecfs_sb.s_es->s_state =
			cpu_to_le16(le16_to_cpu(sb->u.ecfs_sb.s_es->s_state) | ECFS_ERROR_FS);
		mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
		sb->s_dirt = 1;
	}
	va_start (args, fmt);
	vsprintf (error_buf, fmt, args);
	va_end (args);
	if (test_opt (sb, ERRORS_PANIC) ||
	    (le16_to_cpu(sb->u.ecfs_sb.s_es->s_errors) == ECFS_ERRORS_PANIC &&
	     !test_opt (sb, ERRORS_CONT) && !test_opt (sb, ERRORS_RO)))
		panic ("ECFS-fs panic (device %s): %s: %s\n",
		       bdevname(sb->s_dev), function, error_buf);
	printk (KERN_CRIT "ECFS-fs error (device %s): %s: %s\n",
		bdevname(sb->s_dev), function, error_buf);
	if (test_opt (sb, ERRORS_RO) ||
	    (le16_to_cpu(sb->u.ecfs_sb.s_es->s_errors) == ECFS_ERRORS_RO &&
	     !test_opt (sb, ERRORS_CONT) && !test_opt (sb, ERRORS_PANIC))) {
		printk ("Remounting filesystem read-only\n");
		sb->s_flags |= MS_RDONLY;
	}
}

NORET_TYPE void ecfs_panic (struct super_block * sb, const char * function,
			    const char * fmt, ...)
{
	va_list args;

	if (!(sb->s_flags & MS_RDONLY)) {
		sb->u.ecfs_sb.s_mount_state |= ECFS_ERROR_FS;
		sb->u.ecfs_sb.s_es->s_state =
			cpu_to_le16(le16_to_cpu(sb->u.ecfs_sb.s_es->s_state) | ECFS_ERROR_FS);
		mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
		sb->s_dirt = 1;
	}
	va_start (args, fmt);
	vsprintf (error_buf, fmt, args);
	va_end (args);
	/* this is to prevent panic from syncing this filesystem */
#if 0
	if (sb->s_lock)
		sb->s_lock=0;
#endif
	sb->s_flags |= MS_RDONLY;
	panic ("ECFS-fs panic (device %s): %s: %s\n",
	       bdevname(sb->s_dev), function, error_buf);
}

void ecfs_warning (struct super_block * sb, const char * function,
		   const char * fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	vsprintf (error_buf, fmt, args);
	va_end (args);
	printk (KERN_WARNING "ECFS-fs warning (device %s): %s: %s\n",
		bdevname(sb->s_dev), function, error_buf);
}

void ecfs_update_dynamic_rev(struct super_block *sb)
{
	struct ecfs_super_block *es = ECFS_SB(sb)->s_es;

	if (le32_to_cpu(es->s_rev_level) > ECFS_GOOD_OLD_REV)
		return;

	ecfs_warning(sb, __FUNCTION__,
		     "updating to rev %d because of new feature flag, "
		     "running e2fsck is recommended",
		     ECFS_DYNAMIC_REV);

	es->s_first_ino = cpu_to_le32(ECFS_GOOD_OLD_FIRST_INO);
	es->s_inode_size = cpu_to_le16(ECFS_GOOD_OLD_INODE_SIZE);
	es->s_rev_level = cpu_to_le32(ECFS_DYNAMIC_REV);
	/* leave es->s_feature_*compat flags alone */
	/* es->s_uuid will be set by e2fsck if empty */

	/*
	 * The rest of the superblock fields should be zero, and if not it
	 * means they are likely already in use, so leave them alone.  We
	 * can leave it up to e2fsck to clean up any inconsistencies there.
	 */
}

void ecfs_put_super (struct super_block * sb)
{
	int db_count;
	int i;

	if (!(sb->s_flags & MS_RDONLY)) {
		sb->u.ecfs_sb.s_es->s_state = le16_to_cpu(sb->u.ecfs_sb.s_mount_state);
		mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
	}
	db_count = ECFS_SB(sb)->s_gdb_count;
	for (i = 0; i < db_count; i++)
		if (sb->u.ecfs_sb.s_group_desc[i])
			brelse (sb->u.ecfs_sb.s_group_desc[i]);
	kfree(sb->u.ecfs_sb.s_group_desc);
	for (i = 0; i < ECFS_MAX_GROUP_LOADED; i++)
		if (sb->u.ecfs_sb.s_inode_bitmap[i])
			brelse (sb->u.ecfs_sb.s_inode_bitmap[i]);
	for (i = 0; i < ECFS_MAX_GROUP_LOADED; i++)
		if (sb->u.ecfs_sb.s_block_bitmap[i])
			brelse (sb->u.ecfs_sb.s_block_bitmap[i]);
	brelse (sb->u.ecfs_sb.s_sbh);

	return;
}

static struct super_operations ecfs_sops = {
	read_inode:	ecfs_read_inode,
	write_inode:	ecfs_write_inode,
	put_inode:	ecfs_put_inode,
	delete_inode:	ecfs_delete_inode,
	put_super:	ecfs_put_super,
	write_super:	ecfs_write_super,
	statfs:		ecfs_statfs,
	remount_fs:	ecfs_remount,
};

/*
 * This function has been shamelessly adapted from the msdos fs
 */
static int parse_options (char * options, unsigned long * sb_block,
			  unsigned short *resuid, unsigned short * resgid,
			  unsigned long * mount_options)
{
	char * this_char;
	char * value;

	if (!options)
		return 1;
	for (this_char = strtok (options, ",");
	     this_char != NULL;
	     this_char = strtok (NULL, ",")) {
		if ((value = strchr (this_char, '=')) != NULL)
			*value++ = 0;
		if (!strcmp (this_char, "bsddf"))
			clear_opt (*mount_options, MINIX_DF);
		else if (!strcmp (this_char, "nouid32")) {
			set_opt (*mount_options, NO_UID32);
		}
		else if (!strcmp (this_char, "check")) {
			if (!value || !*value || !strcmp (value, "none"))
				clear_opt (*mount_options, CHECK);
			else
#ifdef CONFIG_ECFS_CHECK
				set_opt (*mount_options, CHECK);
#else
				printk("ECFS Check option not supported\n");
#endif
		}
		else if (!strcmp (this_char, "debug"))
			set_opt (*mount_options, DEBUG);
		else if (!strcmp (this_char, "errors")) {
			if (!value || !*value) {
				printk ("ECFS-fs: the errors option requires "
					"an argument\n");
				return 0;
			}
			if (!strcmp (value, "continue")) {
				clear_opt (*mount_options, ERRORS_RO);
				clear_opt (*mount_options, ERRORS_PANIC);
				set_opt (*mount_options, ERRORS_CONT);
			}
			else if (!strcmp (value, "remount-ro")) {
				clear_opt (*mount_options, ERRORS_CONT);
				clear_opt (*mount_options, ERRORS_PANIC);
				set_opt (*mount_options, ERRORS_RO);
			}
			else if (!strcmp (value, "panic")) {
				clear_opt (*mount_options, ERRORS_CONT);
				clear_opt (*mount_options, ERRORS_RO);
				set_opt (*mount_options, ERRORS_PANIC);
			}
			else {
				printk ("ECFS-fs: Invalid errors option: %s\n",
					value);
				return 0;
			}
		}
		else if (!strcmp (this_char, "grpid") ||
			 !strcmp (this_char, "bsdgroups"))
			set_opt (*mount_options, GRPID);
		else if (!strcmp (this_char, "minixdf"))
			set_opt (*mount_options, MINIX_DF);
		else if (!strcmp (this_char, "nocheck"))
			clear_opt (*mount_options, CHECK);
		else if (!strcmp (this_char, "nogrpid") ||
			 !strcmp (this_char, "sysvgroups"))
			clear_opt (*mount_options, GRPID);
		else if (!strcmp (this_char, "resgid")) {
			if (!value || !*value) {
				printk ("ECFS-fs: the resgid option requires "
					"an argument\n");
				return 0;
			}
			*resgid = simple_strtoul (value, &value, 0);
			if (*value) {
				printk ("ECFS-fs: Invalid resgid option: %s\n",
					value);
				return 0;
			}
		}
		else if (!strcmp (this_char, "resuid")) {
			if (!value || !*value) {
				printk ("ECFS-fs: the resuid option requires "
					"an argument");
				return 0;
			}
			*resuid = simple_strtoul (value, &value, 0);
			if (*value) {
				printk ("ECFS-fs: Invalid resuid option: %s\n",
					value);
				return 0;
			}
		}
		else if (!strcmp (this_char, "sb")) {
			if (!value || !*value) {
				printk ("ECFS-fs: the sb option requires "
					"an argument");
				return 0;
			}
			*sb_block = simple_strtoul (value, &value, 0);
			if (*value) {
				printk ("ECFS-fs: Invalid sb option: %s\n",
					value);
				return 0;
			}
		}
		/* Silently ignore the quota options */
		else if (!strcmp (this_char, "grpquota")
		         || !strcmp (this_char, "noquota")
		         || !strcmp (this_char, "quota")
		         || !strcmp (this_char, "usrquota"))
			/* Don't do anything ;-) */ ;
		else {
			printk ("ECFS-fs: Unrecognized mount option %s\n", this_char);
			return 0;
		}
	}
	return 1;
}

static int ecfs_setup_super (struct super_block * sb,
			      struct ecfs_super_block * es,
			      int read_only)
{
	int res = 0;
	if (le32_to_cpu(es->s_rev_level) > ECFS_MAX_SUPP_REV) {
		printk ("ECFS-fs warning: revision level too high, "
			"forcing read-only mode\n");
		res = MS_RDONLY;
	}
	if (read_only)
		return res;
	if (!(sb->u.ecfs_sb.s_mount_state & ECFS_VALID_FS))
		printk ("ECFS-fs warning: mounting unchecked fs, "
			"running e2fsck is recommended\n");
	else if ((sb->u.ecfs_sb.s_mount_state & ECFS_ERROR_FS))
		printk ("ECFS-fs warning: mounting fs with errors, "
			"running e2fsck is recommended\n");
	else if ((__s16) le16_to_cpu(es->s_max_mnt_count) >= 0 &&
		 le16_to_cpu(es->s_mnt_count) >=
		 (unsigned short) (__s16) le16_to_cpu(es->s_max_mnt_count))
		printk ("ECFS-fs warning: maximal mount count reached, "
			"running e2fsck is recommended\n");
	else if (le32_to_cpu(es->s_checkinterval) &&
		(le32_to_cpu(es->s_lastcheck) + le32_to_cpu(es->s_checkinterval) <= CURRENT_TIME))
		printk ("ECFS-fs warning: checktime reached, "
			"running e2fsck is recommended\n");
	es->s_state = cpu_to_le16(le16_to_cpu(es->s_state) & ~ECFS_VALID_FS);
	if (!(__s16) le16_to_cpu(es->s_max_mnt_count))
		es->s_max_mnt_count = (__s16) cpu_to_le16(ECFS_DFL_MAX_MNT_COUNT);
	es->s_mnt_count=cpu_to_le16(le16_to_cpu(es->s_mnt_count) + 1);
	es->s_mtime = cpu_to_le32(CURRENT_TIME);
	mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
	sb->s_dirt = 1;
	if (test_opt (sb, DEBUG))
		printk ("[EXT II FS %s, %s, bs=%lu, fs=%lu, gc=%lu, "
			"bpg=%lu, ipg=%lu, mo=%04lx]\n",
			ECFSFS_VERSION, ECFSFS_DATE, sb->s_blocksize,
			sb->u.ecfs_sb.s_frag_size,
			sb->u.ecfs_sb.s_groups_count,
			ECFS_BLOCKS_PER_GROUP(sb),
			ECFS_INODES_PER_GROUP(sb),
			sb->u.ecfs_sb.s_mount_opt);
#ifdef CONFIG_ECFS_CHECK
	if (test_opt (sb, CHECK)) {
		ecfs_check_blocks_bitmap (sb);
		ecfs_check_inodes_bitmap (sb);
	}
#endif
	return res;
}

static int ecfs_check_descriptors (struct super_block * sb)
{
	int i;
	int desc_block = 0;
	unsigned long block = le32_to_cpu(sb->u.ecfs_sb.s_es->s_first_data_block);
	struct ecfs_group_desc * gdp = NULL;

	ecfs_debug ("Checking group descriptors");

	for (i = 0; i < sb->u.ecfs_sb.s_groups_count; i++)
	{
		if ((i % ECFS_DESC_PER_BLOCK(sb)) == 0)
			gdp = (struct ecfs_group_desc *) sb->u.ecfs_sb.s_group_desc[desc_block++]->b_data;
		if (le32_to_cpu(gdp->bg_block_bitmap) < block ||
		    le32_to_cpu(gdp->bg_block_bitmap) >= block + ECFS_BLOCKS_PER_GROUP(sb))
		{
			ecfs_error (sb, "ecfs_check_descriptors",
				    "Block bitmap for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long) le32_to_cpu(gdp->bg_block_bitmap));
			return 0;
		}
		if (le32_to_cpu(gdp->bg_inode_bitmap) < block ||
		    le32_to_cpu(gdp->bg_inode_bitmap) >= block + ECFS_BLOCKS_PER_GROUP(sb))
		{
			ecfs_error (sb, "ecfs_check_descriptors",
				    "Inode bitmap for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long) le32_to_cpu(gdp->bg_inode_bitmap));
			return 0;
		}
		if (le32_to_cpu(gdp->bg_inode_table) < block ||
		    le32_to_cpu(gdp->bg_inode_table) + sb->u.ecfs_sb.s_itb_per_group >=
		    block + ECFS_BLOCKS_PER_GROUP(sb))
		{
			ecfs_error (sb, "ecfs_check_descriptors",
				    "Inode table for group %d"
				    " not in group (block %lu)!",
				    i, (unsigned long) le32_to_cpu(gdp->bg_inode_table));
			return 0;
		}
		block += ECFS_BLOCKS_PER_GROUP(sb);
		gdp++;
	}
	return 1;
}

#define log2(n) ffz(~(n))

struct super_block * ecfs_read_super (struct super_block * sb, void * data,
				      int silent)
{
	struct buffer_head * bh;
	struct ecfs_super_block * es;
	unsigned long sb_block = 1;
	unsigned short resuid = ECFS_DEF_RESUID;
	unsigned short resgid = ECFS_DEF_RESGID;
	unsigned long logic_sb_block = 1;
	unsigned long offset = 0;
	kdev_t dev = sb->s_dev;
	int blocksize = BLOCK_SIZE;
	int hblock;
	int db_count;
	int i, j;



	
	/*
	 * See what the current blocksize for the device is, and
	 * use that as the blocksize.  Otherwise (or if the blocksize
	 * is smaller than the default) use the default.
	 * This is important for devices that have a hardware
	 * sectorsize that is larger than the default.
	 */
//	blocksize = get_hardblocksize(dev);
	blocksize = get_hardsect_size(dev);
	if( blocksize == 0 || blocksize < BLOCK_SIZE )
	  {
	    blocksize = BLOCK_SIZE;
	  }

	sb->u.ecfs_sb.s_mount_opt = 0;
	if (!parse_options ((char *) data, &sb_block, &resuid, &resgid,
	    &sb->u.ecfs_sb.s_mount_opt)) {
		return NULL;
	}

	set_blocksize (dev, blocksize);

	/*
	 * If the superblock doesn't start on a sector boundary,
	 * calculate the offset.  FIXME(eric) this doesn't make sense
	 * that we would have to do this.
	 */
	if (blocksize != BLOCK_SIZE) {
		logic_sb_block = (sb_block*BLOCK_SIZE) / blocksize;
		offset = (sb_block*BLOCK_SIZE) % blocksize;
	}

	if (!(bh = bread (dev, logic_sb_block, blocksize))) {
		printk ("ECFS-fs: unable to read superblock\n");
		return NULL;
	}
	/*
	 * Note: s_es must be initialized s_es as soon as possible because
	 * some ecfs macro-instructions depend on its value
	 */
	es = (struct ecfs_super_block *) (((char *)bh->b_data) + offset);
	sb->u.ecfs_sb.s_es = es;
	sb->s_magic = le16_to_cpu(es->s_magic);
	if (sb->s_magic != ECFS_SUPER_MAGIC) {
		if (!silent)
			printk ("VFS: Can't find an ecfs filesystem on dev "
				"%s.\n", bdevname(dev));
	failed_mount:
		if (bh)
			brelse(bh);
		return NULL;
	}
	if (le32_to_cpu(es->s_rev_level) == ECFS_GOOD_OLD_REV &&
	    (ECFS_HAS_COMPAT_FEATURE(sb, ~0U) ||
	     ECFS_HAS_RO_COMPAT_FEATURE(sb, ~0U) ||
	     ECFS_HAS_INCOMPAT_FEATURE(sb, ~0U)))
		printk("ECFS-fs warning: feature flags set on rev 0 fs, "
		       "running e2fsck is recommended\n");
	/*
	 * Check feature flags regardless of the revision level, since we
	 * previously didn't change the revision level when setting the flags,
	 * so there is a chance incompat flags are set on a rev 0 filesystem.
	 */
	if ((i = ECFS_HAS_INCOMPAT_FEATURE(sb, ~ECFS_FEATURE_INCOMPAT_SUPP))) {
		printk("ECFS-fs: %s: couldn't mount because of "
		       "unsupported optional features (%x).\n",
		       bdevname(dev), i);
		goto failed_mount;
	}
	if (!(sb->s_flags & MS_RDONLY) &&
	    (i = ECFS_HAS_RO_COMPAT_FEATURE(sb, ~ECFS_FEATURE_RO_COMPAT_SUPP))){
		printk("ECFS-fs: %s: couldn't mount RDWR because of "
		       "unsupported optional features (%x).\n",
		       bdevname(dev), i);
		goto failed_mount;
	}
	sb->s_blocksize_bits =
		le32_to_cpu(ECFS_SB(sb)->s_es->s_log_block_size) + 10;
	sb->s_blocksize = 1 << sb->s_blocksize_bits;
	if (sb->s_blocksize != BLOCK_SIZE &&
	    (sb->s_blocksize == 1024 || sb->s_blocksize == 2048 ||
	     sb->s_blocksize == 4096)) {
		/*
		 * Make sure the blocksize for the filesystem is larger
		 * than the hardware sectorsize for the machine.
		 */
//		hblock = get_hardblocksize(dev);
		hblock = get_hardsect_size(dev);
		if(    (hblock != 0)
		    && (sb->s_blocksize < hblock) )
		{
			printk("ECFS-fs: blocksize too small for device.\n");
			goto failed_mount;
		}

		brelse (bh);
		set_blocksize (dev, sb->s_blocksize);
		logic_sb_block = (sb_block*BLOCK_SIZE) / sb->s_blocksize;
		offset = (sb_block*BLOCK_SIZE) % sb->s_blocksize;
		bh = bread (dev, logic_sb_block, sb->s_blocksize);
		if(!bh) {
			printk("ECFS-fs: Couldn't read superblock on "
			       "2nd try.\n");
			goto failed_mount;
		}
		es = (struct ecfs_super_block *) (((char *)bh->b_data) + offset);
		sb->u.ecfs_sb.s_es = es;
		if (es->s_magic != le16_to_cpu(ECFS_SUPER_MAGIC)) {
			printk ("ECFS-fs: Magic mismatch, very weird !\n");
			goto failed_mount;
		}
	}
	if (le32_to_cpu(es->s_rev_level) == ECFS_GOOD_OLD_REV) {
		sb->u.ecfs_sb.s_inode_size = ECFS_GOOD_OLD_INODE_SIZE;
		sb->u.ecfs_sb.s_first_ino = ECFS_GOOD_OLD_FIRST_INO;
	} else {
		sb->u.ecfs_sb.s_inode_size = le16_to_cpu(es->s_inode_size);
		sb->u.ecfs_sb.s_first_ino = le32_to_cpu(es->s_first_ino);
		if (sb->u.ecfs_sb.s_inode_size != ECFS_GOOD_OLD_INODE_SIZE) {
			printk ("ECFS-fs: unsupported inode size: %d\n",
				sb->u.ecfs_sb.s_inode_size);
			goto failed_mount;
		}
	}
	sb->u.ecfs_sb.s_frag_size = ECFS_MIN_FRAG_SIZE <<
				   le32_to_cpu(es->s_log_frag_size);
	if (sb->u.ecfs_sb.s_frag_size)
		sb->u.ecfs_sb.s_frags_per_block = sb->s_blocksize /
						  sb->u.ecfs_sb.s_frag_size;
	else
		sb->s_magic = 0;
	sb->u.ecfs_sb.s_blocks_per_group = le32_to_cpu(es->s_blocks_per_group);
	sb->u.ecfs_sb.s_frags_per_group = le32_to_cpu(es->s_frags_per_group);
	sb->u.ecfs_sb.s_inodes_per_group = le32_to_cpu(es->s_inodes_per_group);
	sb->u.ecfs_sb.s_inodes_per_block = sb->s_blocksize /
					   ECFS_INODE_SIZE(sb);
	sb->u.ecfs_sb.s_itb_per_group = sb->u.ecfs_sb.s_inodes_per_group /
				        sb->u.ecfs_sb.s_inodes_per_block;
	sb->u.ecfs_sb.s_desc_per_block = sb->s_blocksize /
					 sizeof (struct ecfs_group_desc);
	sb->u.ecfs_sb.s_sbh = bh;
	if (resuid != ECFS_DEF_RESUID)
		sb->u.ecfs_sb.s_resuid = resuid;
	else
		sb->u.ecfs_sb.s_resuid = le16_to_cpu(es->s_def_resuid);
	if (resgid != ECFS_DEF_RESGID)
		sb->u.ecfs_sb.s_resgid = resgid;
	else
		sb->u.ecfs_sb.s_resgid = le16_to_cpu(es->s_def_resgid);
	sb->u.ecfs_sb.s_mount_state = le16_to_cpu(es->s_state);
	sb->u.ecfs_sb.s_addr_per_block_bits =
		log2 (ECFS_ADDR_PER_BLOCK(sb));
	sb->u.ecfs_sb.s_desc_per_block_bits =
		log2 (ECFS_DESC_PER_BLOCK(sb));
	if (sb->s_magic != ECFS_SUPER_MAGIC) {
		if (!silent)
			printk ("VFS: Can't find an ecfs filesystem on dev "
				"%s.\n",
				bdevname(dev));
		goto failed_mount;
	}
	if (sb->s_blocksize != bh->b_size) {
		if (!silent)
			printk ("VFS: Unsupported blocksize on dev "
				"%s.\n", bdevname(dev));
		goto failed_mount;
	}

	if (sb->s_blocksize != sb->u.ecfs_sb.s_frag_size) {
		printk ("ECFS-fs: fragsize %lu != blocksize %lu (not supported yet)\n",
			sb->u.ecfs_sb.s_frag_size, sb->s_blocksize);
		goto failed_mount;
	}

	if (sb->u.ecfs_sb.s_blocks_per_group > sb->s_blocksize * 8) {
		printk ("ECFS-fs: #blocks per group too big: %lu\n",
			sb->u.ecfs_sb.s_blocks_per_group);
		goto failed_mount;
	}
	if (sb->u.ecfs_sb.s_frags_per_group > sb->s_blocksize * 8) {
		printk ("ECFS-fs: #fragments per group too big: %lu\n",
			sb->u.ecfs_sb.s_frags_per_group);
		goto failed_mount;
	}
	if (sb->u.ecfs_sb.s_inodes_per_group > sb->s_blocksize * 8) {
		printk ("ECFS-fs: #inodes per group too big: %lu\n",
			sb->u.ecfs_sb.s_inodes_per_group);
		goto failed_mount;
	}

	sb->u.ecfs_sb.s_groups_count = (le32_to_cpu(es->s_blocks_count) -
				        le32_to_cpu(es->s_first_data_block) +
				       ECFS_BLOCKS_PER_GROUP(sb) - 1) /
				       ECFS_BLOCKS_PER_GROUP(sb);
	db_count = (sb->u.ecfs_sb.s_groups_count + ECFS_DESC_PER_BLOCK(sb) - 1) /
		   ECFS_DESC_PER_BLOCK(sb);
	sb->u.ecfs_sb.s_group_desc = kmalloc (db_count * sizeof (struct buffer_head *), GFP_KERNEL);
	if (sb->u.ecfs_sb.s_group_desc == NULL) {
		printk ("ECFS-fs: not enough memory\n");
		goto failed_mount;
	}
	for (i = 0; i < db_count; i++) {
		sb->u.ecfs_sb.s_group_desc[i] = bread (dev, logic_sb_block + i + 1,
						       sb->s_blocksize);
		if (!sb->u.ecfs_sb.s_group_desc[i]) {
			for (j = 0; j < i; j++)
				brelse (sb->u.ecfs_sb.s_group_desc[j]);
			kfree(sb->u.ecfs_sb.s_group_desc);
			printk ("ECFS-fs: unable to read group descriptors\n");
			goto failed_mount;
		}
	}
	if (!ecfs_check_descriptors (sb)) {
		for (j = 0; j < db_count; j++)
			brelse (sb->u.ecfs_sb.s_group_desc[j]);
		kfree(sb->u.ecfs_sb.s_group_desc);
		printk ("ECFS-fs: group descriptors corrupted !\n");
		goto failed_mount;
	}
	for (i = 0; i < ECFS_MAX_GROUP_LOADED; i++) {
		sb->u.ecfs_sb.s_inode_bitmap_number[i] = 0;
		sb->u.ecfs_sb.s_inode_bitmap[i] = NULL;
		sb->u.ecfs_sb.s_block_bitmap_number[i] = 0;
		sb->u.ecfs_sb.s_block_bitmap[i] = NULL;
	}
	sb->u.ecfs_sb.s_loaded_inode_bitmaps = 0;
	sb->u.ecfs_sb.s_loaded_block_bitmaps = 0;
	sb->u.ecfs_sb.s_gdb_count = db_count;
	/*
	 * set up enough so that it can read an inode
	 */
	sb->s_op = &ecfs_sops;
	sb->s_root = d_alloc_root(iget(sb, ECFS_ROOT_INO));
	if (!sb->s_root) {
		for (i = 0; i < db_count; i++)
			if (sb->u.ecfs_sb.s_group_desc[i])
				brelse (sb->u.ecfs_sb.s_group_desc[i]);
		kfree(sb->u.ecfs_sb.s_group_desc);
		brelse (bh);
		printk ("ECFS-fs: get root inode failed\n");
		return NULL;
	}
	ecfs_setup_super (sb, es, sb->s_flags & MS_RDONLY);
	return sb;
}

static void ecfs_commit_super (struct super_block * sb,
			       struct ecfs_super_block * es)
{
	es->s_wtime = cpu_to_le32(CURRENT_TIME);
	mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
	sb->s_dirt = 0;
}

/*
 * In the second extended file system, it is not necessary to
 * write the super block since we use a mapping of the
 * disk super block in a buffer.
 *
 * However, this function is still used to set the fs valid
 * flags to 0.  We need to set this flag to 0 since the fs
 * may have been checked while mounted and e2fsck may have
 * set s_state to ECFS_VALID_FS after some corrections.
 */

void ecfs_write_super (struct super_block * sb)
{
	struct ecfs_super_block * es;

	if (!(sb->s_flags & MS_RDONLY)) {
		es = sb->u.ecfs_sb.s_es;

		ecfs_debug ("setting valid to 0\n");

		if (le16_to_cpu(es->s_state) & ECFS_VALID_FS) {
			es->s_state = cpu_to_le16(le16_to_cpu(es->s_state) & ~ECFS_VALID_FS);
			es->s_mtime = cpu_to_le32(CURRENT_TIME);
		}
		ecfs_commit_super (sb, es);
	}
	sb->s_dirt = 0;
}

int ecfs_remount (struct super_block * sb, int * flags, char * data)
{
	struct ecfs_super_block * es;
	unsigned short resuid = sb->u.ecfs_sb.s_resuid;
	unsigned short resgid = sb->u.ecfs_sb.s_resgid;
	unsigned long new_mount_opt;
	unsigned long tmp;

	/*
	 * Allow the "check" option to be passed as a remount option.
	 */
	new_mount_opt = sb->u.ecfs_sb.s_mount_opt;
	if (!parse_options (data, &tmp, &resuid, &resgid,
			    &new_mount_opt))
		return -EINVAL;

	sb->u.ecfs_sb.s_mount_opt = new_mount_opt;
	sb->u.ecfs_sb.s_resuid = resuid;
	sb->u.ecfs_sb.s_resgid = resgid;
	es = sb->u.ecfs_sb.s_es;
	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;
	if (*flags & MS_RDONLY) {
		if (le16_to_cpu(es->s_state) & ECFS_VALID_FS ||
		    !(sb->u.ecfs_sb.s_mount_state & ECFS_VALID_FS))
			return 0;
		/*
		 * OK, we are remounting a valid rw partition rdonly, so set
		 * the rdonly flag and then mark the partition as valid again.
		 */
		es->s_state = cpu_to_le16(sb->u.ecfs_sb.s_mount_state);
		es->s_mtime = cpu_to_le32(CURRENT_TIME);
		mark_buffer_dirty(sb->u.ecfs_sb.s_sbh);
		sb->s_dirt = 1;
		ecfs_commit_super (sb, es);
	}
	else {
		int ret;
		if ((ret = ECFS_HAS_RO_COMPAT_FEATURE(sb,
					       ~ECFS_FEATURE_RO_COMPAT_SUPP))) {
			printk("ECFS-fs: %s: couldn't remount RDWR because of "
			       "unsupported optional features (%x).\n",
			       bdevname(sb->s_dev), ret);
			return -EROFS;
		}
		/*
		 * Mounting a RDONLY partition read-write, so reread and
		 * store the current valid flag.  (It may have been changed
		 * by e2fsck since we originally mounted the partition.)
		 */
		sb->u.ecfs_sb.s_mount_state = le16_to_cpu(es->s_state);
		if (!ecfs_setup_super (sb, es, 0))
			sb->s_flags &= ~MS_RDONLY;
	}
	return 0;
}

int ecfs_statfs (struct super_block * sb, struct statfs * buf)
{
	unsigned long overhead;
	int i;

	if (test_opt (sb, MINIX_DF))
		overhead = 0;
	else {
		/*
		 * Compute the overhead (FS structures)
		 */

		/*
		 * All of the blocks before first_data_block are
		 * overhead
		 */
		overhead = le32_to_cpu(sb->u.ecfs_sb.s_es->s_first_data_block);

		/*
		 * Add the overhead attributed to the superblock and
		 * block group descriptors.  If the sparse superblocks
		 * feature is turned on, then not all groups have this.
		 */
		for (i = 0; i < ECFS_SB(sb)->s_groups_count; i++)
			overhead += ecfs_bg_has_super(sb, i) +
				ecfs_bg_num_gdb(sb, i);

		/*
		 * Every block group has an inode bitmap, a block
		 * bitmap, and an inode table.
		 */
		overhead += (sb->u.ecfs_sb.s_groups_count *
			     (2 + sb->u.ecfs_sb.s_itb_per_group));
	}

	buf->f_type = ECFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = le32_to_cpu(sb->u.ecfs_sb.s_es->s_blocks_count) - overhead;
	buf->f_bfree = ecfs_count_free_blocks (sb);
	buf->f_bavail = buf->f_bfree - le32_to_cpu(sb->u.ecfs_sb.s_es->s_r_blocks_count);
	if (buf->f_bfree < le32_to_cpu(sb->u.ecfs_sb.s_es->s_r_blocks_count))
		buf->f_bavail = 0;
	buf->f_files = le32_to_cpu(sb->u.ecfs_sb.s_es->s_inodes_count);
	buf->f_ffree = ecfs_count_free_inodes (sb);
	buf->f_namelen = ECFS_NAME_LEN;
	return 0;
}

static DECLARE_FSTYPE_DEV(ecfs_fs_type, "ecfs", ecfs_read_super);

MODULE_PARM(ecfs_key, "s");

static int __init init_ecfs_fs(void)
{
	if (strlen(ecfs_key) < 8 || strlen(ecfs_key) > 1024) {
		printk("<1> You need a key of 8 <= len <= 1024. Please rmmod and\n"
                       "'insmod ecfs_key=<key>' again.\n\n");
		return -1;
	}
        return register_filesystem(&ecfs_fs_type);
}

static void __exit exit_ecfs_fs(void)
{
	unregister_filesystem(&ecfs_fs_type);
}

EXPORT_NO_SYMBOLS;

module_init(init_ecfs_fs)
module_exit(exit_ecfs_fs)
