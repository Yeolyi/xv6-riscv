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

-   p->state indicates whether the process is allocated, ready to run, running, waiting for I/O, or exiting.
-   p->pagetable holds the process’s page table, in the format that the RISC-V hardware expects.

p는 proc 구조체를 의미

In summary, a process bundles two design ideas: an address space to give a process the illusion of its own memory, and, a thread, to give the process the illusion of its own CPU. In xv6, a process consists of one address space and one thread.

### 2.6 Code: starting xv6, the first process and system call

컴퓨터가 켜지면 스스로를 initialize하고 ROM에 있는 부트 로더를 실행.

부트로더가 xv6 커널을 메모리에 로드. 0x80000000에 위치하는데 그 이전에는 I/O devices가 있음.

머신 모드에서 \_entry(entry.S)에서 시작하는 xv6 실행.

The code at \_entry loads the stack pointer register sp with the address stack0+4096, the top of the stack, because the stack on RISC-V grows down.

\_entry에서 C 스택 생성, start 함수 실행

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

-   system call(ecall)
-   exception
-   device interrupt

(timer interrupt는?)

This book uses trap as a generic term for these situations.

We often want traps to be transparent.

Xv6 handles all traps in the kernel; traps are not delivered to user code.

Xv6 trap handling proceeds in four stages:

1. hardware actions taken by the RISC-V CPU,
1. some assembly instructions that prepare the way for kernel C code,
1. a C function that decides what to do with the trap,
1. system call or device-driver service routine.

it turns out to be convenient to have separate code for three distinct cases:

-   traps from user space
-   traps from kernel space
-   and timer interrupts.

Kernel code (assembler or C) that processes a trap is often called a handler; the first handler instructions are usually written in assembler (rather than C) and are sometimes called a **vector**.

### 4.1 RISC-V trap machinery

Each RISC-V CPU has a set of control registers that the kernel writes to tell the CPU how to handle traps, and that the kernel can read to find out about a trap that has occurred.

머신 모드용 control register도 있지만 타이머 인터럽트 등 제한된 상황에서만 사용한다.

Each CPU on a multi-core chip has its own set of these registers, and more than one CPU may be handling a trap at any given time.

Note that the CPU doesn’t switch to the kernel page table, doesn’t switch to a stack in the kernel, and doesn’t save any registers other than the pc.

### 4.2 Traps from user space

uservec(trampoline.S) -> usertrap(trap.c) -> usertrapret(trap.c) -> userret(trampoline.S)

RISC-V 하드웨어가 page table을 바꿔주지 않기 때문에 stvec의 주소는 user page table에서도 유효한 주소여야한다. 또한 trap handler에서 커널 페이지로 바뀌어야하기 때문에 kernel page table에서도 유효해야한다. 이를 위해 trampoline 페이지를 사용한다. 여기에 uservec이 있다.

The kernel allocates, for each process, a page of memory for a trapframe structure that (among other things) has space to save the 32 user registers (kernel/proc.h:43)

The process’s p->trapframe also points to the trapframe, though at its physical address so the kernel can use it through the kernel page table.

### 4.3 Code: Calling system calls

ecall -> uservec -> usertrap -> syscall

syscall (kernel/syscall.c:132) retrieves the system call number from the saved a7 **in the trapframe** and uses it to index into syscalls.

예시: initCode.S

### 4.4 Code: System call arguments

The kernel functions argint, argaddr, and argfd retrieve the n ’th system call argument from the trap frame as an integer, pointer, or a file descriptor.

몇몇 system call은 exec처럼 유저 공간에 있는 포인터 배열등을 인자로 전달할 수 있다. 이경우 악의적인 포인터일 수도 있고, user page table을 사용해야한다는 문제가 있다. 이에 fetchstr과 copyinstr를 사용한다.

### 4.5 Traps from kernel space

When the kernel is executing on a CPU, the kernel points stvec to the assembly code at kernelvec (kernel/kernelvec.S:12).

kernelvec saves the registers on the stack of the interrupted kernel thread, which makes sense because the register values belong to that thread. This is particularly important if the trap causes a switch to a different thread – in that case the trap will actually return from the stack of the new thread, leaving the interrupted thread’s saved registers safely on its stack??

**It’s worth thinking through how the trap return happens if kerneltrap called yield due to a timer interrupt.**

### 4.6 Page-fault exceptions

Xv6’s response to exceptions is quite boring: if an exception happens in user space, the kernel kills the faulting process. If an exception happens in the kernel, the kernel panics.

실제로는 잘 활용하는데, page fault를 통해 copy-on-write fork를 구현할 수 있다.

RISC-V에는 아래의 page fault가 있다.

-   load page fault
-   store page fault
-   instruction page fault

scause에 원인이 있고 stval에 문제가 된 주소가 있다.

...The kernel’s trap handler responds by allocating a new page of physical memory and copying into it the physical page that the faulted address maps to. Copy-on-write requires book-keeping to help decide when physical pages can be freed, since each page can be referenced

Another widely-used feature is called lazy allocation. Lazy allocation allows this cost to be spread over time. On the other hand, lazy allocation incurs the extra overhead of page faults, which involve a kernel/user transi- tion.

Yet another widely-used feature that exploits page faults is demand paging. To improve response time, a modern kernel creates the page table for the user address space, but marks the PTEs for the pages invalid.

The programs running on a computer may need more memory than the computer has RAM. To cope gracefully, the operating system may implement paging to disk.

...The idea is to store only a fraction of user pages in RAM, and to store the rest on disk in a paging area.

Other features that combine paging and page-fault exceptions include automatically extending stacks and memory-mapped files.

### 4.7 Real world

And the trap handler is initially ignorant of useful facts such as the identity of the process that’s running or the address of the kernel page table??

The need for special trampoline pages could be eliminated if kernel memory were mapped into every process’s user page table. ? 이랬다가 지금 형태로 바뀐거라고 그러지 않았나. Xv6 avoids them in order to reduce the chances of security bugs in the kernel due to inadvertent use of user pointers, and to reduce some complexity that would be required to ensure that user and kernel virtual addresses don’t overlap.

https://www.sobyte.net/post/2022-01/xv6-riscv-kpti/

## 5. Interupts and device drivers

A driver is the code in an operating system that manages a particular device: it configures the device hardware, tells the device to perform operations, handles the resulting interrupts, and interacts with processes that may be waiting for I/O from the device.

...in xv6, this dispatch happens in devintr (kernel/trap.c:178).

Many device drivers execute code in two contexts: a top half that runs in a process’s kernel thread, and a bottom half that executes at interrupt time.

The top half is called via system calls such as read and write that want the device to perform I/O. This code may ask the hardware to start an operation (e.g., ask the disk to read a block); then the code waits for the operation to complete.

Eventually the device completes the operation and raises an interrupt. The driver’s interrupt handler, acting as the bottom half, figures out what operation has completed, wakes up a waiting process if appropriate, and tells the hardware to start work on any waiting next operation.

### 5.1 Console input

The UART hardware appears to software as a set of memory-mapped control registers. That is, there are some physical addresses that RISC-V hardware connects to the UART device, so that loads and stores interact with the device hardware rather than RAM.

Xv6’s main calls consoleinit (kernel/console.c:182) to initialize the UART hardware.

The xv6 shell reads from the console by way of a file descriptor opened by init.c (user/init.c:19). Calls to the read system call make their way through the kernel to consoleread

너무 재미없어서 다음에,,

## 6. Locking

...These multiple CPUs share physical RAM, and xv6 exploits the sharing to maintain data structures that all CPUs read and write?

The word concurrency refers to situations in which multiple instruction streams are interleaved, due to multiprocessor parallelism, thread switching, or interrupts.

Strategies aimed at correctness under concurrency, and abstractions that support them, are called concurrency control techniques.

This chapter focuses on a widely used technique: the lock.

If the programmer associates a lock with each shared data item, and the code always holds the associated lock when using an item, then the item will be used by only one CPU at a time.

The downside of locks is that they can limit performance, because they serialize concurrent operations.

The rest of this chapter explains why xv6 needs locks, how xv6 implements them, and how it uses them.

### 6.1 Races

A race is a situation in which a memory location is accessed concurrently, and at least one access is a write.

...For example, adding print statements while debugging push might change the timing of the execution enough to make the race disappear.

Locks ensure mutual exclusion, so that only one CPU at a time can execute the sensitive lines of...

The sequence of instructions between acquire and release is often called a critical section.

When we say that a lock protects data, we really mean that the lock protects some collection of **invariants** that apply to the data.

Proper use of a lock ensures that only one CPU at a time can operate on the data structure in the critical section, so that no CPU will execute a data structure operation when the data structure’s invariants do not hold.

We say that multiple processes conflict if they want the same lock at the same time, or that the lock experiences contention

### 6.2 Code: Locks

Xv6 has two types of locks: spinlocks and sleep-locks.

```c
// multiprocessor에서 동작하지 않는다
void acquire(struct spinlock *lk) {
    for(;;) {
        // 아래 두 줄을 amoswap 명령어로 실행한다.
        if (lk->locked == 0) {
            lk->locked = 1;
            break;
        }
    }
}
```

The C standard allows compilers to implement an assignment with multiple store instructions, so a C assignment might be non-atomic with respect to concurrent code. 따라서 release도 \_\_sync_lock_release를 사용한다.

### 6.3 Code: Using locks

-   First, any time a variable can be written by one CPU at the same time that another CPU can read or write it, a lock should be used to keep the two operations from overlapping.
-   Second, remember that locks protect invariants: if an invariant involves multiple memory locations, typically all of them need to be protected by a single lock to ensure the invariant is maintained.

big kernel lock은 pipe read나 wait같은 blocking system calls에서 문제가 생긴다?

As an example of coarse-grained locking, xv6’s kalloc.c allocator has a single free list pro- tected by a single lock.

As an example of fine-grained locking, xv6 has a separate lock for each file, so that processes that manipulate different files can often proceed without waiting for each other’s locks.

### 6.4 Deadlock and lock ordering

If a code path through the kernel must hold several locks at the same time, it is important that all code paths acquire those locks in the **same order**. If they don’t, there is a risk of **deadlock**.

locks are effectively part of each function’s specification

creating a file requires simultaneously holding a lock on the directory, a lock on the new file’s inode, a lock on a disk block buffer, the disk driver’s vdisk_lock, and the calling pro- cess’s p->lock.

### 6.5 Re-entrant locks

It might appear that some deadlocks and lock-ordering challenges could be avoided by using reentrant locks(or recursive locks). If the lock is held by a process and if that process attempts to acquire the lock again, then the kernel could just allow this instead of panic.

하지만 atomic하지 못하게 하는 경우가 있어서 쓰지 않았다.

### 6.6 Locks and interrupt handlers

The interaction of spinlocks and interrupts raises a potential danger. 예를 들어 sys_sleep에서 tickslock을 가지고 있는 상태에서 timer interrupt가 걸리면 끝나지 않는다.

To avoid this situation, if a spinlock is used by an interrupt handler, a CPU must never hold that lock with interrupts enabled. Xv6 is more conservative: when a CPU acquires any lock, xv6 always disables interrupts on that CPU. Interrupts may still occur on other CPUs, so an interrupt’s acquire can wait for a thread to release a spinlock; just not on the same CPU.

push off와 pop off로 nesting level of lock을 감지하고 0이 되면 interrupt를 재활성화시킨다.

### 6.7 Instruction and memory ordering

여러 스레드가 공유 메모리로 상호작용하는 상황에서는 프로그램이 순서대로 실행되지 않을 수도 있다. 컴파일러가 ld, st 순서를 바꿀 수 있고 최적화과정에서 없앨 수도 있다. CPU도 out of order execution이 가능하다.

The good news is that compilers and CPUs help concurrent programmers by following a set of rules called the memory model, and by providing some primitives to help programmers control re-ordering.

xv6에서는 \_\_sync_synchronize()를 acquire와 release에서 사용한다. memory barrier이다.

### 6.8 Sleep locks

Sometimes xv6 needs to hold a lock for a long time.

spinlock은 이경우 돌면서 CPU를 낭비시키고 spinlock을 가지고 있는 상태에서 CPU를 yield할 수 없다는 단점이 있다.

Yielding while holding a spinlock is illegal because it might lead to deadlock if a second thread then tried to acquire the spinlock; **since acquire doesn’t yield the CPU**, the second thread’s spinning might prevent the first thread from running and releasing the lock.

Thus we’d like a type of lock that yields the CPU while waiting to acquire, and allows yields (and interrupts) while the lock is held. - sleep locks.

Because sleep-locks leave interrupts enabled, they cannot be used in interrupt handlers. Because acquiresleep may yield the CPU, sleep-locks cannot be used inside spinlock critical sections.

락은 xv6 맥락에서는 cpu간에 공유하기 위해 쓰는건가?

Spin-locks are best suited to short critical sections, since waiting for them wastes CPU time; sleep-locks work well for lengthy operations.

### 6.9 Real world

It is often best to conceal locks within higher-level constructs like synchronized queues, although xv6 does not do this.

Most operating systems support POSIX threads (Pthreads), which allow a user process to have several threads running concurrently on different CPUs.

It is possible to implement locks without atomic instructions [10], but it is expensive, and most operating systems use atomic instructions.

To avoid the expenses associated with locks, many operating systems use lock-free data struc- tures and algorithms.

## 7. Scheduling

Any operating system is likely to run with more processes than the computer has CPUs, so a plan is needed to time-share the CPUs among the processes.

### 7.1 Multiplexing

Implementing multiplexing poses a few challenges:

1. Although the idea of context switching is simple, the implementation is some of the most opaque code in xv6.
1. Second, how to force switches in a way that is transparent to user processes? Xv6 uses the standard technique in which a hardware timer’s interrupts drive context switches.
1. Third, all of the CPUs switch among the same shared set of processes, and a locking plan is necessary to avoid races.
1. Fourth, a process’s memory and other resources must be freed when the process exits, but it cannot do all of this itself because (for example) it can’t free its own kernel stack while still using it.
1. Fifth, each core of a multi-core machine must remember which process it is executing so that system calls affect the correct process’s kernel state.
1. Finally, sleep and wakeup allow a process to give up the CPU and wait to be woken up by another process or interrupt. Care is needed to avoid races that result in the loss of wakeup notifications.

### 7.2 Code: Context switching

1. a user-kernel transition (system call or interrupt) to the old process’s kernel thread
1. a context switch to the current CPU’s scheduler thread
1. a context switch to a new process’s kernel thread
1. a trap return to the user-level process.

xv6에는 스케쥴러를 위한 쓰레드가 CPU마다 있는데 because it is not safe for the scheduler to execute on the old process’s kernel stack: some other core might wake the process up and run it, and it would be a disaster to use the same stack on two different cores.

The function swtch performs the saves and restores for a kernel thread switch.

context는 프로세스의 struct proc이나 cpu의 struct cpu에 있다.

usertrap->yield->sched->swtch

그나저나 c로 쓴거랑 S로 쓴거랑 기준이 뭐임?

### 7.3 Code: Scheduling

The scheduler exists in the form of a special thread per CPU, each running the scheduler function.

A process that wants to give up the CPU must acquire its own process lock p->lock, release any other locks it is holding, update its own state (p->state), and then call sched(yield, sleep, exit).

xv6 holds p->lock across calls to swtch: the caller of swtch must already hold the lock, and control of the lock passes to the switched-to code. 일반적으로는 한 스레드에서 락을 얻고 푼다.

The only place a kernel thread gives up its CPU is in sched, and it always switches to the same location in scheduler, which (almost) always switches to some kernel thread that previously called sched.

Procedures that intentionally transfer control to each other via thread switch are sometimes referred to as **coroutines**; in this example, sched and scheduler are co-routines of each other.

otherwise, since the new process needs to return to user space as if returning from fork, it could instead start at usertrapret??

One way to think about the structure of the scheduling code is that it enforces a set of invariants about each process, and holds p->lock whenever those invariants are not true.

Maintaining the above invariants is the reason why xv6 often acquires p->lock in one thread and releases it in another, for example acquiring in yield and releasing in scheduler.

### 7.4 Code: mycpu and myproc

xv6는 CPU마다 struct cpu를 관리한다.

-   process running (if exists)
-   saved registers for the CPU's schedular thread
-   count of nested spinlocks needed to manage interrupt disabling

mycpu()는 위 구조체로의 포인터를 반환한다.

riscv는 각 cpu마다 hartid를 부여한다. xv6는 얘네를 tp 레지스터에 저장한다.

-   start sets the tp register early in the CPU’s boot sequence, while still in machine mode (kernel/start.c:51).
-   usertrapret saves tp in the trampoline page, because the user process might modify tp.
-   Finally, uservec restores that saved tp when entering the kernel from user space (kernel/trampoline.S:77).
-   The compiler guarantees never to use the tp register.

cpuid/mycpu를 얻어왔는데 다른 CPU로 옮겨가면 안되니 struct cpu를 사용하는 동안 interrupt를 막도록한다.

Thereturnvalue of myproc is safe to use even if interrupts are enabled: if a timer interrupt moves the calling process toadifferentCPU,itsstruct procpointerwillstaythesame?? 같은 값이면 의미가 있나?

### 7.5 Sleep and wakeup

Scheduling and locks help conceal the actions of one thread from another, but we also need abstractions that help threads intentionally interact.

The xv6 kernel uses a mechanism called sleep and wakeup in these situations (and many others).

Sleep and wakeup are often called sequence coordination or conditional synchronization mechanisms.

Lock을 이용한 세마포어의 구현은 producer가 가끔씩 동작한다면 consumer쪽에서의 시간 낭비가 크다.

sleep(chan) sleeps on the arbitrary value chan, called the wait channel. sleep puts the calling process to sleep, releasing the CPU for other work. wakeup(chan) wakes all processes sleeping on chan (if any), causing their sleep calls to return.

```c
void P(struct semaphore *s) { 
  while(s->count == 0) 
    // 이 시점에 다른 CPU에서 count를 늘렸을 수도 있다. 
    // lose wake-up problem
    sleep(s);
  acquire(&s->lock);
  s->count -= 1;
  release(&s->lock);
}
```

The root of this problem is that the invariant that P only sleeps when s->count == 0 is violated by V running at just the wrong moment.

We’ll fix the preceding scheme by changing sleep’s interface: the caller must pass the condition lock to sleep so it can release the lock after the calling process is marked as asleep and waiting on the sleep channel. 

The lock will force a concurrent V to wait until P has finished putting itself to sleep, so that the wakeup will find the sleeping consumer and wake it up. Once the consumer is awake again **sleep reacquires the lock before returning**. 

Note, however, that we need sleep to atomically release s->lock and put the consuming process to sleep, in order to avoid lost wakeups??

### 7.6 Code: Sleep and wakeup

## 8. File system

The purpose of a file system is to organize and store data. File systems typically support sharing of data among users and applications, as well as persistence so that data is still available after a reboot.

- on-disk data structures to represent the tree of named directories and files, to record the identities of the blocks that hold each file’s content, and to record which areas of the disk are free.
- must support crash recovery
- Different processes may operate on the file system at the same time, so the file-system code must coordinate to maintain invariants.
- file system must maintain an in-memory cache of popular blocks.

The rest of this chapter explains how xv6 addresses these challenges.

### 8.1 Overview

xv6's seven layers:

- File descriptor: abstracts many Unix resources(pipes, devices, files...)
- Pathname: hierarchial path names
- Directory: directory as a special kine of inode
- Inode: individual files
- Logging: higher layers to wrap updates the several blocks in a **transaction**, ensures that the blocks are updated atomically in the face of rashes(all of them are updated or none)
- Buffer cache: making sure that only one kernel process at a time and modify
- Disk: r/w on an virtio hard drive

Disk hardware traditionally presents the data on the disk as a numbered sequence of 512-byte blocks (also called **sectors**).

The block size that an operating system uses for its file system maybe different than the sector size that a disk uses, but typically the block size is a multiple of the sector size.

Xv6 holds copies of blocks that it has read into memory in objects of type `struct buf`.

bitmap blocks tracking which data blocks are in use. 

The superblock is filled in by a separate program, called mkfs, which builds an initial file system.

### 8.2 Buffer cache layer

- synchronize access to disk blocks to ensure that only one copy of a block is in memory and that only one kernel thread at a time uses that copy
- cache popular blocks so that they don’t need to be re-read from the slow disk.

The buffer cache uses a per-buffer sleep-lock to ensure that only one thread at a time uses each buffer (and thus each disk block);

읽는건 다같이해도 괜찮은거겠지? - bget보니까 아닌거같기도 하고?

### 8.3 Code: Buffer cache

The buffer cache is a doubly-linked list of buffers.



## 9. Concurrency revisited

