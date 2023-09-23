# Initial process that execs /init.
# This code runs in user space.

# loads the number for the exec system call, 
# SYS_EXEC (kernel/syscall.h:8), into register a7, 
# and then calls ecall to re-enter the kernel.

# 커널은 a7에 있는 수를 syscall에서 사용해 desired system call을 호출한다.
# The system call table (kernel/syscall.c:107) maps
# SYS_EXEC to sys_exec, which the kernel invokes.

#include "syscall.h"

# exec(init, argv)
.globl start
start:
        la a0, init
        la a1, argv
        li a7, SYS_exec
        ecall

# for(;;) exit();
exit:
        li a7, SYS_exit
        ecall
        jal exit

# char init[] = "/init\0";
init:
  .string "/init\0"

# char *argv[] = { init, 0 };
.p2align 2
argv:
  .long init
  .long 0
