---
title: pwn总结
date: 2021-08-01
tags: 漏洞分析
---

## 栈溢出

### 过NX

No-eXecute，表示不可执行，其原理是将数据所在的内存页标识为不可执行，如果程序产生溢出转入执行 shellcode 时，CPU 会抛出异常。

在 Linux 中，当装载器将程序装载进内存空间后，将程序的 .text 段标记为可执行，而其余的数据段（.data、.bss 等）以及栈、堆均为不可执行。因此，传统利用方式中通过修改 GOT 来执行 shellcode 的方式不再可行。

使用ROP，ret2libc

### 过PIE，ASLR

地址空间布局随机化（ASLR），该技术虽然不是由 GCC 编译时提供的，但对 PIE 还是有影响。该技术旨在将程序的内存布局随机化，使得攻击者不能轻易地得到数据区的地址来构造 payload。由于程序的堆栈分配与共享库的装载都是在运行时进行，系统在程序每次执行时，随机地分配程序堆栈的地址以及共享库装载的地址。使得攻击者无法预测自己写入的数据区的虚拟地址。

针对该保护机制的攻击，往往是通过信息泄漏来实现。由于同一模块中的所有代码和数据的相对偏移是固定的，攻击者只要泄漏出某个模块中的任一代码指针或数据指针，即可通过计算得到此模块中任意代码或数据的地址。

PIE（Position Independent Executable）其实就是把可执行文件给编译成动态链接库，需要配合 ASLR 来使用，以达到可执行文件的加载时地址随机化。简单来说，PIE 是编译时随机化，由编译器完成；ASLR 是加载时随机化，由操作系统完成。ASLR 将程序运行时的堆栈以及共享库的加载地址随机化，而 PIE 在编译时将程序编译为位置无关、即程序运行时各个段加载的虚拟地址在装载时确定。开启 PIE 时，编译生成的是动态库文件（Shared object）文件，而关闭 PIE 后生成可执行文件（Executable）

需要把地址泄漏出来

### 过canary

-fno-stack-protector 关闭canary检测
-fstack-protector 打开canary检测

通过泄漏地址或者

### RELRO

RELRO（ReLocation Read-Only）设置符号重定向表为只读或在程序启动时就解析并绑定所有动态符号，从而减少对 GOT（Global Offset Table）的攻击。

RELOR 有两种形式：

- Partial RELRO：一些段（包括 `.dynamic`）在初始化后将会被标记为只读。
- Full RELRO：除了 Partial RELRO，延迟绑定将被禁止，所有的导入符号将在开始时被解析，`.got.plt` 段会被完全初始化为目标函数的最终地址，并被标记为只读。另外 `link_map` 和 `_dl_runtime_resolve` 的地址也不会被装入。

## 编译参数

各种安全技术的编译参数如下：

| 安全技术 | 完全开启 | 部分开启 | 关闭 |
| --- | --- | --- | --- |
| Canary | -fstack-protector-all | -fstack-protector | -fno-stack-protector |
| NX | -z noexecstack | | -z execstack |
| PIE | -pie | | -no-pie |
| RELRO | -z now | -z lazy | -z norelro |
