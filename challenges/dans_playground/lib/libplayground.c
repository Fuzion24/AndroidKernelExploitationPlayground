/*
 * libplayground userland library
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

#include <fcntl.h>
#include <sys/ioctl.h>
#include "playground.h"

/* Global file descriptor to device file */
int playgroundfd;

int playground_init(void)
{
	playgroundfd = open("/dev/playground", O_RDONLY);

	return playgroundfd;
}

int playground_close(void)
{
	return close(playgroundfd);
}

int kmalloc(unsigned int index, unsigned int size)
{
	struct playground_args args;

	args.slot = index;
	args.size = size;

	return ioctl(playgroundfd, PLAYGROUND_ALLOC, &args);
}

int kmalloc_fill(unsigned int index, unsigned int size, unsigned char fill)
{
	struct playground_args args;

	args.slot = index;
	args.size = size;
	args.fill = fill;

	return ioctl(playgroundfd, PLAYGROUND_ALLOCFILL, &args);
}

int ktrigger(unsigned int index, unsigned int offset)
{
	struct playground_args args;

	args.slot = index;
	args.offset = offset;

	return ioctl(playgroundfd, PLAYGROUND_TRIGGER, &args);
}

int kwrite(unsigned int index, unsigned int size, char *data)
{
	struct playground_args args;

	args.slot = index;
	args.size = size;
	args.ptr = data;

	return ioctl(playgroundfd, PLAYGROUND_COPYIN, &args);
}

int kread(unsigned int index, unsigned int size, char *data)
{
	struct playground_args args;

	args.slot = index;
	args.size = size;
	args.ptr = data;

	return ioctl(playgroundfd, PLAYGROUND_COPYOUT, &args);
}

int kfree(unsigned int index)
{
	struct playground_args args;

	args.slot = index;

	return ioctl(playgroundfd, PLAYGROUND_FREE, &args);
}

int kdoublefree(unsigned int index)
{
	struct playground_args args;

	args.slot = index;

	return ioctl(playgroundfd, PLAYGROUND_DOUBLEFREE, &args);
}
