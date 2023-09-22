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

## 3. Page tables

## 4. Traps and system calls

## 5. Interupts and device drivers

## 6. Locking

## 7. Scheduling

## 8. File system

## 9. Concurrency revisited

## 10. Summary
