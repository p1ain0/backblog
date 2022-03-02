
## seccomp



## Breaking out

通常来讲只有沙盒进程能够和特权进程\(privileged process\)通信，才会有用。这就意味着，一般情况下沙盒进程能够使用一些系统调用。这就为一些攻击提供了可能性。

### permissive policies

Reasons:

1. System calls非常的庞大且复杂；
2. 开发人员为了避免破坏功能，会对限制作宽容处理。

An Well-known example:ptrace()

根据系统配置，允许ptrace()的系统调用可以让沙盒进程去操纵一个非沙盒进程。一旦ptrace后，你就可以修改内存，寄存器，让进程暂停开始......

Some less well-know effects:

sendmsg() 可以再程序之间传输文件描述符。
prctl()
process_vm_writev() 允许直接访问其他进程的内存。

### syscall confusion

很多64位架构会向后兼容32位的程序。
amd64/x86_64 | x86
     aarch64 | arm
      mips64 | mips
   powerpc64 | ppc
     sparc64 | sparc

在一些cpu上，可以在32位模式和64位模式之间切换，在相同的进程中，因此内核必须为两种模式都提供好接口。有趣的是在这两种架构中，系统调用号是不同的；同时允许32位和64位的策略可能会在一种模式（32位/6位4）里边失败。

### kernel vulnerabilities in the syscall handlers

