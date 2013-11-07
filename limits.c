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
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/module.h>



MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Access non-exported symbols");
MODULE_AUTHOR("Stephen Zhang");





static int limit_file_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 0;
}

static int limit_file_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 0;
}

static int limit_file_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 0;
}

static int limit_file_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	printk(KERN_INFO "Limit File: limit file inode.\n");
	return 0;
}



static int cap_inode_create(struct inode *inode, struct dentry *dentry,
			    int mask)
{
	printk(KERN_INFO "Limit File: inode create.\n");
	return 0;
}


static int cap_inode_mkdir(struct inode *inode, struct dentry *dentry,
			   int mask)
{
	printk(KERN_INFO "Limit File: inode mkdir.\n");
	return 0;
}


static int cap_inode_mknod(struct inode *inode, struct dentry *dentry,
			   int mode, dev_t dev)
{
	printk(KERN_INFO "Limit File: inode mknod.\n");
	return 0;
}

static struct security_operations limit_file_ops = {
	.name =				"limit_files",

	.inode_create =			cap_inode_create,
	.inode_link =			limit_file_inode_link,
	.inode_unlink =			limit_file_inode_unlink,
	.inode_symlink =		limit_file_inode_symlink,
	.inode_mkdir =			cap_inode_mkdir,
	.inode_mknod =			cap_inode_mknod,
	.inode_rename =			limit_file_inode_rename,

};


unsigned long sym_addr = 0;

int search_function(void * data, const char *sym_name, struct module * mod, unsigned long addres){
	char *lookup_sym_name = (char *) data;

	if (strcmp(lookup_sym_name, sym_name) == 0){
		sym_addr = addres;
		return 1;
	}
	return 0;
}


static int __init limit_files_init(void)
{
	char *sym_name = "register_security";

	typedef int register_security(struct security_operations *);
	register_security *f;

	kallsyms_on_each_symbol(search_function, sym_name);

	if (!sym_addr)
		panic("Limit File: Unable to get register_security address.\n");

	f = (void *) sym_addr;

	if (f(&limit_file_ops))
		panic("Limit File: Unable to register with kernel.\n");

	printk(KERN_INFO "[%s] %s (0x%lx)\n", __this_module.name, sym_name, sym_addr);

	return 0;
}

static void __exit limit_files_exit(void)
{
}

module_init(limit_files_init);
module_exit(limit_files_exit);




