---
title: "xv6: a simple, Unix-like teaching operating system"
---

## 1. Operating system interfaces

Other documentation (e.g., the RISC-V specification) also uses the words processor, core, and hart instead of CPU.

This chapter outlines xv6’s services —processes, memory, file descriptors, pipes, and a file system— and illustrates them with code snippets and discussions of how the shell, Unix’s command-line user interface, uses them. The shell’s use of system calls illustrates how carefully they have been designed.

The fact that the shell is a user program, and not part of the kernel, illustrates the power of the system call interface: there is nothing special about the shell.

The xv6 shell is a simple implementation of the essence of the Unix Bourne shell.

### 1.1 Processes and memory

An xv6 process consists of user-space memory (instructions, data, and stack) and per-process state private to the kernel?? 커널에게 private하다는게 무슨 뜻이지.

-   int fork(): create a process, return child's PID
-   int exit(int status): Terminate the current process; status reported to wait(). No return.
-   int wait(int *status) wait for a child to exit; exit status in *status; returns child PID
-   int kill(int pid): Terminate process PID. returns 0, or -1 for error.
-   int getpid(): Return the current process's PID
-   int sleep(int n): Pause for n clock ticks.
-   int exec(char *file, char *argv[]): Load a file and execute it with arguments; only returns if error
-   char \*sbrk(int n): Grow process's memory by n bytes. Returns start of new memory.
-   int open(char \*file, int flags): OPen a file; flags indicate read/write; returns an fd.
-   int write(int fd, char \*buf, int n): Write n bytes from buf to file descriptor fd; returns n.
-   int read(int fd, char \*buf, int n): Read n bytes into buf; returns number read; or 0 if end of file
-   int close(int fd): Release open file fd.
-   int dup(int fd): Return a new file descriptor referring to the same file as fd.
-   int pipe(int p[]) Create a pipe, put read/write file desciptors in p[0] and p[1]
-   int chdir(char \*dir): Change the current directory
-   int mkdir(char \*dir): Create a new directory.
-   int fstat(int fd, struct stat): Place info about an open file into \*st.
-   int stat(char *file, struct stat *st)
-   int link(char *file1, char *file2) Create another name (file2) for the file file1.
-   int unlink(char \*file)

wait는 어떤 자식 프로세스를 기다림?

chdir, mkdir 이런건 프로그램 내에서 쓸 일이 있나? shell에서 쓰는거 아님?

Exit takes an integer status argument, conventionally 0 to indicate success and 1 to indicate failure.

If the parent doesn’t care about the exit status of a child, it can pass a 0 address to wait.

Xv6 uses the ELF format.

You might wonder why fork and exec are not combined in a single call; we will see later that the shell exploits the separation in its implementation of I/O redirection. Virtual memory를 활용한 cow로 최적화할 수 있다.

xv6는 대부분의 유저 공간 메모리를 fork와 exec내부에서 암시적으로 처리하지만 필요하다면 sbrk를 호출할 수 있다. 

### 1.2 I/O and File descriptors

Internally, the xv6 kernel uses the file descriptor as an index into a per-process table, so that every process has a private space of file descriptors starting at zero.

The shell ensures that it always has three file descriptors open (user/sh.c:152), which are by default file descriptors for the console? 정확히 세개가 열려있도록 함. 

Each file descriptor that refers to a file has an offset associated with it.

In write call, fewer than n bytes are written only when an error occurs.

The use of file descriptors and the convention that file descriptor 0 is input and file descriptor 1 is output allows a simple implementation of cat. A newly allocated file descriptor is always the lowest- numbered unused descriptor of the current process.

fork가 file descriptor table을 유지시키기에 shell에서 이를 통해 I/O redirection을 구현할 수 있다. fork 이후에 0을 닫고 파일을 열면 그 파일이 input으로서 역할한다. 

Now it should be clear why it is helpful that fork and exec are separate calls: between the two, the shell has a chance to redirect the child’s I/O without disturbing the I/O setup of the main shell.

file offset이 공유된다?? fork나 dup으로 인해 같은 file descriptor로부터 온게 아니라면 공유하지 않는다. 

```c
// 이런 코드 보면 공유되는게 맞긴 한듯
if(fork() == 0) {
    write(1, "hello ", 6);
    exit(0);
} else {
    wait(0);
    write(1, "world\n", 6);
}
```

```
(echo hello; echo world) > output.txt.
```

dup allows shells to implement commands like this: ls existing-file non-existing-file > tmp1 2>&1.

File descriptors are a powerful abstraction, because they hide the details of what they are connected to.

### 1.3 Pipes

A pipe is a small kernel buffer exposed to processes as a pair of file descriptors, one for reading and one for writing.

Pipes provide a way for processes to communicate.

The fact that read blocks until it is impossible for new data to arrive is one reason that it’s important for the child to close the write end of the pipe before executing wc above: if one of wc ’s file descriptors referred to the write end of the pipe, wc would never see end-of-file.

### 1.4 File system

Paths that don’t begin with / are evaluated relative to the calling process’s current directory, which can be changed with the chdir system call

mknod creates a special file that refers to a device. Associated with a device file are the major and minor device numbers (the two arguments to mknod), which uniquely identify a kernel device. When a process later opens a device file, the kernel diverts read and write system calls to the kernel device implementation instead of passing them to the file system. major와 minor의 차이는?

A file’s name is distinct from the file itself; the same underlying file, called an **inode**, can have multiple names, called **links**. 트리가 아닐텐데 어떻게 구현한거지? 암튼 fstat으로 inode의 내용을 가져올 수 있다. 

The link system call creates another file system name referring to the same inode as an existing file. 

Unix provides file utilities callable from the shell as **user-level programs**, for example mkdir, ln, and rm. 커널에 박혀있는게 아니라 유저 레벨 프로그램으로 존재해서 수정할 수 있다. 예외적으로 cd는 쉘의 cwd를 바꿔야돼서 쉘에 박혀있다. 

### 1.5 Real world

쉘은 최초의 scripting language로 불린다. 

The Unix system call interface has been standardized through the Portable Operating System Interface (POSIX) standard.

Xv6 does not provide a notion of users or of protecting one user from another; in Unix terms, all xv6 processes run as root.

Any operating system must multiplex processes onto the underlying hardware, isolate processes from each other, and provide mechanisms for controlled inter-process communication. 

https://stackoverflow.com/a/19265380

## 2. Operating system organization

...Thus an operating system must fulfill three requirements: multiplexing, isolation, and interaction.

프로세스간 독립적이어야되지만 소통은 되어야한다. 

This chapter provides an overview of how operating systems are organized to achieve these three requirements. monolothic kernel 기준. multi-core RISC-V microprocessor. LP64 C, long과 pointer가 64비트. 

Xv6 is written for the support hardware simulated by qemu’s “-machine virt” option. This includes RAM, a ROM containing boot code, a serial connection to the user’s keyboard/screen, and a disk for storage.

### 1. Abstracting physical resources

To achieve strong isolation it’s helpful to forbid applications from directly accessing sensitive hardware resources, and instead to abstract the resources into services. For example, Unix applica- tions interact with storage only through the file system’s open, read, write, and close system calls.

Unix processes use exec to build up their memory image, instead of directly interacting with physical memory. exec also provides users with the convenience of a file system to store executable program images?

The Unix interface is not the only way to abstract resources, but it has proven to be a very good one.

### 2. User mode, supervisor mode, and system calls

RISC-V has three modes in which the CPU can execute instructions: machine mode, supervisor mode, and user mode.

Machine mode는 configuring computer의 의도로 사용된다. xv6에서는 몇 줄 이렇게 하고 supervisor로 옮긴다. 

supervisor에서는 privileged insturction의 실행이 가능하다. 이 시점에 소프트웨어는 kernel space에 있다고 한다. **Kernel space, 혹은 supervisor mode에서 동작하는 소프트웨어를 kernel로 부른다.**

ecall로 supervisor mode로 바꾼다. 

### 2.3 Kernel organization

A key design question is what part of the operating system should run in supervisor mode. One possibility is that the entire operating system resides in the kernel, so that the implementations of all system calls run in supervisor mode. This organization is called a **monolithic kernel**.

To reduce the risk of mistakes in the kernel, OS designers can minimize the amount of operating system code that runs in supervisor mode, and execute the bulk of the operating system in user mode. This kernel organization is called a **microkernel**.

Xv6 is implemented as a monolithic kernel, like most Unix operating systems. **Thus, the xv6 kernel interface corresponds to the operating system interface, and the kernel implements the com- plete operating system.**

### 2.4 Code: xv6 organization

커널 파일마다 주석 넣는 것으로 대체.

### 2.5 Process overview

The unit of isolation in xv6 (as in other Unix operating systems) is a process.

The mechanisms used by the kernel to implement processes include the user/supervisor mode flag, address spaces, and time-slicing of threads.

Xv6 uses page tables (which are implemented by hardware) to give each process its own ad- dress space. 

Pointers on the RISC-V are 64 bits wide; the hardware only uses the low 39 bits when looking up virtual addresses in page tables; and xv6 only uses 38 of those 39 bits. Thus, the maximum address is 238 − 1 = 0x3fffffffff, which is MAXVA. 

trampoline과 trapframe은 커널로 오고가기위해 필요하다. 전자는 이를 위한 코드, 후자는 유저 프로세스 상태를 백업하기 위함. 

Each process has a thread of execution (or thread for short) that executes the process’s instructions.

When the process enters the kernel (for a system call or interrupt), the kernel code executes on the process’s kernel stack

ecal / sret

- p->state indicates whether the process is allocated, ready to run, running, waiting for I/O, or exiting.
- p->pagetable holds the process’s page table, in the format that the RISC-V hardware expects.

p는 proc 구조체를 의미

In summary, a process bundles two design ideas: an address space to give a process the illusion of its own memory, and, a thread, to give the process the illusion of its own CPU. In xv6, a process consists of one address space and one thread.

### 2.6 Code: starting xv6, the first process and system call

컴퓨터가 켜지면 스스로를 initialize하고 ROM에 있는 부트 로더를 실행.

부트로더가 xv6 커널을 메모리에 로드. 0x80000000에 위치하는데 그 이전에는 I/O devices가 있음. 

머신 모드에서 _entry(entry.S)에서 시작하는 xv6 실행.

The code at _entry loads the stack pointer register sp with the address stack0+4096, the top of the stack, because the stack on RISC-V grows down.

_entry에서 C 스택 생성, start 함수 실행

start함수에서 machine mode에서만 가능한 작업 수행, supervisor mode로 변경, supervisor mode로 돌아가는 척하는 환경 설정으로 하고? main으로 이동

After main (kernel/main.c:11) initializes several devices and subsystems, it creates the first process by calling userinit.

/init 프로세스를 만들고 console device file을 만들고 0, 1, 2에 연다. 

entry.S는 0x8...에 qemu가 올린다 치고, 나머지 것들은? 컴파일 링크할 때 한 덩어리가 돼서 한번에 올라가는건가. 

### 2.7 Security Model

The operating system must assume that a process’s user-level code will do its best to wreck the kernel or other processes.

Kernel code is expected to be bug-free, and certainly to contain nothing malicious. This assumption affects how we analyze kernel code. For example, there are many internal kernel functions (e.g., the spin locks) that would cause serious problems if kernel code used them incorrectly. 

Finally, the dis- tinction between user and kernel code is sometimes blurred: some privileged user-level processes may provide essential services and effectively be part of the operating system, and in some oper- ating systems privileged user code can insert new code into the kernel (as with Linux’s loadable kernel modules).

### 2.8 Real world

실제로는 프로세스당 여러개의 쓰레드가 있다. 리눅스의 clone과 같은 추가적인 인터페이스가 필요하다. 

## 3. Page tables

Xv6 performs a few tricks: mapping the same memory (a trampoline page) in several address spaces, and guarding kernel and user stacks with an unmapped page. The rest of this chapter explains the page tables that the RISC-V hardware provides and how xv6 uses them.

### 3.1 Paging hardware

유저와 커널 모두 가상 주소로 작업한다. 

Xv6 runs on Sv39 RISC-V, which means that only the bottom 39 bits of a 64-bit virtual address are used; the top 25 bits are not used. 

The paging hardware translates a virtual address by using the top 27 bits of the 39 bits to index into the page table to find a PTE, and making a 56-bit physical address whose top 44 bits come from the PPN in the PTE and whose bottom 12 bits are copied from the original virtual address.

A page table is stored in physical memory as a three-level tree. 

...a potential downside of three levels is that the CPU must load three PTEs from memory to perform the translation of the virtual address in the load/store instruction to a physical address. To avoid the cost of loading PTEs from physical memory, a RISC-V CPU caches page table entries in a Translation Look-aside Buffer (TLB).

V가 0이면 접근시 exception. U가 0이면 supervisor에서만 사용할 수 있는 PTE. The flags and all other page hardware-related structures are defined in (kernel/riscv.h)

To tell a CPU to use a page table, the kernel must write the physical address of the root page table page into the satp register.

Each CPU has its own satp so that different CPUs can run different processes, each with a private address space described by its own page table.

Typically a kernel maps all of physical memory into its page table so that it can read and write any location in physical memory using load/store instructions. Since the page directories are in physical memory, the kernel can program the content of a PTE in a page directory by writing to the virtual address of the PTE using a standard store instruction??

https://stackoverflow.com/questions/76255976/riscv-mhartid-register

### 3.2 Kernel address space

The kernel configures the layout of its ad- dress space to give itself access to physical memory and various hardware resources at predictable virtual addresses. 

QEMU simulates a computer that includes RAM (physical memory) starting at physical address 0x80000000 and continuing through at least 0x88000000, which xv6 calls PHYSTOP.

QEMU exposes the device interfaces to software as memory-mapped control registers that sit below 0x80000000 in the physical address space.

The kernel gets at RAM and memory-mapped device registers using “direct mapping”. Direct mapping이 안되는 경우가 있는데, trampoline page는 유저와 커널에서 같은 가상 주소를 가지고 kernel stack page는 guard로 감싸야돼서 또 다른듯?

Direct mapping이 있으니 kernel stack을 이쪽을 통해 바로 사용할 수도 있었겠지만, guard page의 제공이 어렵다. 

Kernel text와 trampoline은 PTE_R, PTE_X이다. 

### 3.3 Code: creating an address space

trampoline.S에 sfence.vma가 있는건 이해가 가는데 kvminithart에는 왜 있지??

### 3.4 Physical memory allocation

Xv6 uses the physical memory between the end of the kernel and PHYSTOP for run-time allocation. Linked list 사용.

### 3.5 Code: Physical memory allocator. 

Wheredoestheallocatorgetthememorytoholdthatdatastruc- ture? It store each free page’s run structure in the free page itself, since there’s nothing else stored there.

Xv6 ought to determine how much physical memory is available by parsing configuration information provided by the hardware. Instead xv6 assumes that the machine has 128 megabytes of RAM.

### 3.6 Process address space

xv6 maps the text without PTE_W; if a program accidentally attempts to store to address 0, the hardware will refuse to execute the store and raises a page fault.

The stack is a single page, and is shown with the initial contents as created by exec.

To detect a user stack overflowing the allocated stack memory, xv6 places an inaccessible guard page right below the stack by clearing the PTE_U flag. A real-world operating system might instead automatically allocate more memory for the user stack when it overflows.

xv6가 메모리를 요청받으면:

1. kalloc으로 physical page를 할당받는다.
1. 프로세스의 page table에 새로운 physical page를 가리키는 PTE를 만든다. 
1. PTE_W, PTE_R, PTE_U, PTE_V를 세팅

...Third, the kernel maps a page with trampoline code at the top of the user address space (without PTE_U), thus a single page of physical memory shows up in all address spaces, but can be used only by the kernel.

### 3.7 Code: sbrk

sbrk is the system call for a process to shrink or grow its memory. The system call is implemented by the function growproc (kernel/proc.c:260).

Xv6 uses a process’s page table not just to tell the hardware how to map user virtual addresses, but also as the only record of which physical memory pages are allocated to that process. That is the reason why freeing user memory (in uvmunmap) requires examination of the user page table.

### 3.8 Code: exec

exec is a system call that replaces a process’s user address space with data read from a file, called a binary or executable file.

Xv6 binaries are formatted in the widely-used ELF format.


A program section header’s filesz may be less than the memsz, indicating that the gap be- tween them should be filled with zeroes (for C global variables) rather than read from the file. For /init, the data filesz is 0x10 bytes and memsz is 0x30 bytes, and thus uvmalloc allocates enough physical memory to hold 0x30 bytes, but reads only 0x10 bytes from the file /init.

```
 seongyeolyi@SEONGui-MacBookPro-2  ~/Developer/xv6-riscv   riscv ±  objdump -p user/_init

user/_init:     file format elf64-littleriscv

Program Header:
 UNKNOWN off    0x0000000000006be7 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**0
         filesz 0x000000000000003e memsz 0x0000000000000000 flags r--
    LOAD off    0x0000000000001000 vaddr 0x0000000000000000 paddr 0x0000000000000000 align 2**12
         filesz 0x0000000000001000 memsz 0x0000000000001000 flags r-x
    LOAD off    0x0000000000002000 vaddr 0x0000000000001000 paddr 0x0000000000001000 align 2**12
         filesz 0x0000000000000010 memsz 0x0000000000000030 flags rw-
```

Users or processes can place whatever addresses they want into an ELF file. Thus exec is risky, because the addresses in the ELF file may refer to the kernel, accidentally or on purpose. 

In an older version of xv6 in which the user address space also contained the kernel (but not readable/writable in user mode), the user could choose an address that corresponded to kernel memory and would thus copy data from the ELF binary into the kernel. In the RISC-V version of xv6 this cannot happen, because the kernel has its own separate page table; loadseg loads into the process’s page table, not in the kernel’s page table.

### 3.9 Real world

...but on real hardware it turns out to be a bad idea; real hardware places RAM and devices at unpredictable physical addresses, so that (for example) there might be no RAM at 0x8000000

The xv6 kernel’s lack of a malloc-like allocator that can provide memory for small objects prevents the kernel from using sophisticated data structures that would require dynamic allocation. A more elaborate kernel would likely allocate many different sizes of small blocks, rather than (as in xv6) just 4096-byte blocks.

## 4. Traps and system calls

CPU가 special code로 control transfer하는 경우:

- system call(ecall)
- exception
- device interrupt

This book uses trap as a generic term for these situations.

We often want traps to be transparent.

Xv6 handles all traps in the kernel; traps are not delivered to user code.

## 5. Interupts and device drivers

## 6. Locking

## 7. Scheduling

## 8. File system

## 9. Concurrency revisited

## 10. Summary
