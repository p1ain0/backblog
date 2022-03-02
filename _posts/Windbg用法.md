---
title: Windbg用法
date: 2021-09-17 14:48:48
tags: 软件调试
---

## 在内核空间和用户空间工作的命令

### dv/dt

当您进行源代码级调试时，可以使用“Display Local Variables”（dv） 命令，或者您可以打开本地变量窗口。

“Display Type”(dt) 命令既可以显示struct的字段，也可以根据给定的struct类型解释给定地址处的内存。

#### 仅显示给定类型struct的顶级字段

```c++

dt {structure type}

0: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
...

```

#### 递归显示struct定义

要递归显示struct（和sub-struct）的字段：

```c++
dt -r{depth} {structure type}

0: kd> dt -r2 nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
      +0x000 Header           : _DISPATCHER_HEADER
         +0x000 Lock             : Int4B
         +0x000 LockNV           : Int4B
         +0x000 Type             : UChar
...

```

#### 按struct显示给定地址出内存中的值：

根据结构定义解释给定地址处的内存：

```c++
dt {structure type} {address}

0: kd> dt nt!_EPROCESS ffffb38b26516340
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0x00000000`00001858 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY [ 0xffffb38b`25aab748 - 0xffffb38b`263da4c8 ]
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : 0x200d080
...
```

### sxe ld

#### 模块加载时中断

Set Exception (sx) 命令可用于在发生特定事件时中断。形式如下：

- Enable: sxe
- Ignore: sxi

可以触发调试器中断的事件有很多，现在只看模块加载，在进行用户空间调试时，“模块”可以是 .exe 或 .dll。 在内核模式下，模块是 .sys 内核驱动程序（或.exe NT的内核本身。）

```c++
sxe ld
```

这条命令会使调试器将在每个模块加载时中断。

#### 在 sx* 中断时自动运行命令

sx*有个可可选的参数 ` -c "some ; list ; of ; commands"`;一个有用的命令是“.lastevent”，它可以打印出关于最后发生的事件的信息。

例如：

```c++
sxe -c ".lastevent" ld
```

如果您只想查看模块何时加载，而不是实际停止（例如，仅查看引导时加载内核驱动程序的顺序），您可以使用：

```c++
sxi -c ".lastevent ; g" ld
```

#### 忽略/禁用断点：

```c++
sxi -c "" ld
```

### lm:List Modules

List Modules (Userspace & Kernel)：

```c++
lm
```

List Modules Userspace only：

```c++
lm u
```

List Modules kernel only：

```c++
lm k
```

List Modules(按字母排序)：

```c++
lm sm
```

列出的模块带着系统路径：

```c++
lm f
```

组合命令输出方式：

```c++
lm ksmf
```

给lm命令加一个v选项，获取冗长的输出信息。

```c++
lm ksmv
```

查看地址属于哪个模块：

```c++
lm a address
```

### !load 加载第三方插件

```c++
!load 
!unload 
```

## kernel-only command

### !process/.process

display 当前进程的context

```c++
!process -1 [flags]
```

列出所有进程的context

```c++
!process 0 [flags]
```

通过进程名查看进程的context

```c++
!process 0 [flags] [exec name]
```

通过进程的pid查看进程context

```c++
!process [pid] [flags]
```

将进程上下文切换为目标进程：

```c++
.process /i /r /p ["PROCESS" address from !process output]
```

### rdmsr/wrmsr: Reading/Writing Model Specific Registers (MSRs)

```c++
rdmsr [MSR #]
wrmsr [MSR #] [value to write]
```

### !ms_gdt: Examine the Global Descriptor Table (GDT)

### !idt/!ms_idt: Examine the Interrupt Descriptor Table (IDT)

### !pte: Examining Virtual Memory and Page Tables

### !pool:

将内存地址与数据结构或驱动程序相关联

### !irql: Examining Windows Interrupt Request Level (IRQL)
