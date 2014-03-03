/*
 * libplayground kernel header file
 * Copyright (C) 2012 Dan Rosenberg
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

#define PLAYGROUND_SIZE 4096

/* Feel free to toggle this if you'd like debug output. This isn't really
 * advisable when testing exploits, because the printk call may alter the state
 * of the heap. */
#undef PLAYGROUND_DEBUG

#ifdef PLAYGROUND_DEBUG
#define PDEBUG(format, args...) printk(KERN_DEBUG "playground: " format, ##args)
#else
#define PDEBUG(format, args...) do { } while (0)
#endif

struct playground_args {
	unsigned int slot;
	unsigned int size;
	unsigned int offset;
	void *ptr;
	unsigned char fill;
};

#define PLAYGROUND_ALLOC	_IOR('P', 1, struct playground_args)
#define PLAYGROUND_FREE		_IOR('P', 2, struct playground_args)
#define PLAYGROUND_DOUBLEFREE	_IOR('P', 3, struct playground_args)
#define PLAYGROUND_COPYIN	_IOR('P', 4, struct playground_args)
#define PLAYGROUND_COPYOUT	_IOWR('P', 5, struct playground_args)
#define PLAYGROUND_ALLOCFILL	_IOR('P', 6, struct playground_args)
#define PLAYGROUND_TRIGGER	_IOR('P', 7, struct playground_args)
