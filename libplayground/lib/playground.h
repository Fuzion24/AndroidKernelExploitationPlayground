/*
 * libplayground userland library header
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


/* Initialize the playground. Returns file descriptor to playground device
 * on success, and -1 on error. */
int playground_init(void);

/* Close the file descriptor to playground device. Returns 0 on success, and
 * -1 on error. */
int playground_close(void);

/* Allocate a chunk of size "size" in slot "index" */
int kmalloc(unsigned int index, unsigned int size);

/* Allocate a chunk of size "size" in slot "index" and fill it with "fill" */
int kmalloc_fill(unsigned int index, unsigned int size, unsigned char fill);

/* Invoke a function pointer stored at word offset "offset" from the chunk
 * in slot "index" */
int ktrigger(unsigned int index, unsigned int offset);

/* Write "size" bytes from "data" into the chunk stored in slot "index" */
int kwrite(unsigned int index, unsigned int size, char *data);

/* Read "size" bytes from the chunk stored in slot "index" into "data" */
int kread(unsigned int index, unsigned int size, char *data);

/* Free the chunk in slot "index" */
int kfree(unsigned int index);

/* Double-free the chunk in slot "index" */
int kdoublefree(unsigned int index);

struct playground_args {
	unsigned int slot;
	unsigned int size;
	unsigned int offset;
	void *ptr;
	unsigned char fill;
};

/* NOTE: make sure these are in sync with the kernel header values */
#define PLAYGROUND_ALLOC	_IOR('P', 1, struct playground_args)
#define PLAYGROUND_FREE		_IOR('P', 2, struct playground_args)
#define PLAYGROUND_DOUBLEFREE	_IOR('P', 3, struct playground_args)
#define PLAYGROUND_COPYIN	_IOR('P', 4, struct playground_args)
#define PLAYGROUND_COPYOUT	_IOWR('P', 5, struct playground_args)
#define PLAYGROUND_ALLOCFILL	_IOR('P', 6, struct playground_args)
#define PLAYGROUND_TRIGGER	_IOR('P', 7, struct playground_args)

