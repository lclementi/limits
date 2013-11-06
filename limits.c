/*
 *  NSA Security-Enhanced Linux (Limit File) security module
 *
 *  This file contains the Limit File hook function implementations.
 *
 *  Authors:  Stephen Smalley, <sds@epoch.ncsc.mil>
 *	      Chris Vance, <cvance@nai.com>
 *	      Wayne Salamon, <wsalamon@nai.com>
 *	      James Morris <jmorris@redhat.com>
 *
 *  Copyright (C) 2001,2002 Networks Associates Technology, Inc.
 *  Copyright (C) 2003-2008 Red Hat, Inc., James Morris <jmorris@redhat.com>
 *					   Eric Paris <eparis@redhat.com>
 *  Copyright (C) 2004-2005 Trusted Computer Solutions, Inc.
 *			    <dgoeddel@trustedcs.com>
 *  Copyright (C) 2006, 2007, 2009 Hewlett-Packard Development Company, L.P.
 *	Paul Moore <paul@paul-moore.com>
 *  Copyright (C) 2007 Hitachi Software Engineering Co., Ltd.
 *		       Yuichi Nakamura <ynakam@hitachisoft.jp>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *	as published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/kd.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>


static int limit_file_enabled;


static int limit_file_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{

	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}

static int limit_file_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 1;
}


static struct security_operations limit_file_ops = {
	.name =				"limit_files",

	.inode_create =			limit_file_inode_create,
	.inode_link =			limit_file_inode_link,
	.inode_unlink =			limit_file_inode_unlink,
	.inode_symlink =		limit_file_inode_symlink,
	.inode_mkdir =			limit_file_inode_mkdir,
	.inode_mknod =			limit_file_inode_mknod,
	.inode_rename =			limit_file_inode_rename,

};

static __init int limit_file_init(void)
{
	if (!security_module_enable(&limit_file_ops)) {
		limit_file_enabled = 0;
		return 0;
	}

	if (!limit_file_enabled) {
		printk(KERN_INFO "Limit File:  Disabled at boot.\n");
		return 0;
	}

	printk(KERN_INFO "Limit File:  Initializing.\n");


	if (register_security(&limit_file_ops))
		panic("Limit File: Unable to register with kernel.\n");

	return 0;
}


security_initcall(limit_file_init);

