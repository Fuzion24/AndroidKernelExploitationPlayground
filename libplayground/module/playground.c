/*
 * libplayground kernel module
 * Copyright (C) 2012 Dan Rosenberg
 * 
 * Warning: this will deliberately introduce vulnerabilities into your kernel
 * for the purposes of exploit development. Additionally, use of this module
 * may, by design, cause corruption of kernel heap memory that may impact
 * system stability, including the integrity of files stored on disk. Use at
 * your own risk.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "playground.h"
#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/sched.h>

static void *playground[PLAYGROUND_SIZE];

static long playground_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct playground_args args;
	int (*pointer)(void);

	if (copy_from_user(&args, (struct playground_args *)arg, sizeof(args)))
		return -EFAULT;

	/* Make sure our deliberately vulnerable module isn't vulnerable :p */
	if (args.slot >= PLAYGROUND_SIZE)
		return -EINVAL;

	switch (cmd) {
	case PLAYGROUND_ALLOC:

		if (playground[args.slot])
			return -EBUSY;
			
		playground[args.slot] = kmalloc(args.size, GFP_KERNEL);

		if (!playground[args.slot])
			return -ENOMEM;

		PDEBUG("Allocated %p in slot %u\n", playground[args.slot], args.slot);

		return 0;

	case PLAYGROUND_ALLOCFILL:

		if (playground[args.slot])
			return -EBUSY;
			
		playground[args.slot] = kmalloc(args.size, GFP_KERNEL);

		if (!playground[args.slot])
			return -ENOMEM;

		PDEBUG("Allocated %p in slot %u\n", playground[args.slot], args.slot);

		memset(playground[args.slot], args.fill, args.size);

		return 0;

	case PLAYGROUND_FREE:

		if (!playground[args.slot])
			return -EINVAL;

		PDEBUG("Freeing %p from slot %u\n", playground[args.slot], args.slot);

		kfree(playground[args.slot]);
		playground[args.slot] = NULL;

		return 0;
	
	case PLAYGROUND_DOUBLEFREE:
	
		if (!playground[args.slot])
			return -EINVAL;

		PDEBUG("Double-freeing %p from slot %u\n", playground[args.slot], args.slot);

		kfree(playground[args.slot]);
		kfree(playground[args.slot]);
		playground[args.slot] = NULL;

		return 0;

	case PLAYGROUND_TRIGGER:

		if (!playground[args.slot])
			return -EINVAL;

		/* Whoa there... */
		pointer = (int (*)(void))*(unsigned long *)(playground[args.slot] + (args.offset * sizeof(void *)));

		PDEBUG("Triggering function pointer to %p\n", pointer);

		pointer();

		return 0;

	case PLAYGROUND_COPYIN:

		if (!playground[args.slot])
			return -EINVAL;

		if (copy_from_user(playground[args.slot], args.ptr, args.size))
			return -EFAULT;

		return 0;

	case PLAYGROUND_COPYOUT:

		if (!playground[args.slot])
			return -EINVAL;

		if (copy_to_user(args.ptr, playground[args.slot], args.size))
			return -EFAULT;

		return 0;
	}

	return -EINVAL;
}

static struct file_operations playground_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = playground_ioctl,
	.compat_ioctl = playground_ioctl,
};

static struct miscdevice playground_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "playground",
	.fops = &playground_fops,
};

static int __init playground_init(void)
{
	int ret;

	ret = misc_register(&playground_misc);
	if (unlikely(ret)) {
		printk(KERN_ERR "playground: failed to register misc device.\n");
		return ret;
	}

	printk(KERN_INFO "playground: initialized\n");

	return 0;
}


static void __exit playground_exit(void)
{
	int ret;

	ret = misc_deregister(&playground_misc);
	if (unlikely(ret))
		printk(KERN_ERR "playground: failed to unregister misc device\n");

	for (ret = 0; ret < PLAYGROUND_SIZE; ret++) {
		if (playground[ret]) {
			kfree(playground[ret]);
			playground[ret] = NULL;
		}
	}

	printk(KERN_INFO "playground: unloaded\n");
}

module_init(playground_init);
module_exit(playground_exit);

MODULE_LICENSE("GPL");
