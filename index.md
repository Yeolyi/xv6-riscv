---
title: "xv6: a simple, Unix-like teaching operating system"
---

## 1. Operating system interfaces

Other documentation (e.g., the RISC-V specification) also uses the words processor, core, and hart instead of CPU.

This chapter outlines xv6’s services —processes, memory, file descriptors, pipes, and a file system— and illustrates them with code snippets and discussions of how the shell, Unix’s command-line user interface, uses them. The shell’s use of system calls illustrates how carefully they have been designed.

The fact that the shell is a user program, and not part of the kernel, illustrates the power of the system call interface: there is nothing special about the shell.

## 2. Operating system organization

## 3. Page tables

## 4. Traps and system calls

## 5. Interupts and device drivers

## 6. Locking

## 7. Scheduling

## 8. File system

## 9. Concurrency revisited

## 10. Summary
