---
title: gdb使用总结
date: 2021-08-03
tags: 软件调试
---

# gdb使用总结

## 一、编译测试程序

```shell
gcc test.c -o test
```

## 二、从磁盘中加载二进制文件

方法1:

```shell
gdb --quite ./test
```

方法2:

```shell
gdb -q
(gdb) file ./test
```

## 三、运行程序

```shell
(gdb) r
```

带CLI参数：

```shell
(gdb) r argv[0] argv[1] ...
```

运行程序并断在入口点处：

```shell
(gdb) start
```

带CLI参数：

```shell
(gdb) start argv[0] ...
```

断点之后继续运行：

```shell
(gdb)c
```

## 四、断点操作

### 设置断点

有符号：

```shell
(gdb) break main
```

or

```shell
(gdb) b main
```

设置地址：

```shell
(gdb) break *addr
```

### 检查断点

```shell
(gdb) info breakpoints
```

or

```shell
(gdb) info b
```

### 禁用启用断点

```shell
(gdb) disable num
```

```shell
(gdb) enable num
```

### 删除断点

```shell
(gdb) clear *addr
```

or

```shell
(gdb) clear main
```

or

"delete \<breakpoint number from info breakpoints\>" (short form: d)

```shell
(gdb) delete 3
```

### 检查汇编代码

```shell
(gdb) disassemble <address or symbol name> /r
#/r显示16进制的数据
```

```shell
(gdb) x/10i <addr>
#显示10条汇编
```

```shell
(gdb) display/10i <instruction pointer / program counter>
#On x86 systems <instruction pointer / program counter> would be $rip
#On ARM systems <instruction pointer / program counter> would be $pc
```

### 监视断点

#### 只写断点

```shell
(gdb) watch <address>
```

#### 只读断点

```shell
(gdb) rwatch <address>
```

#### 读写断点

```shel
awatch <address>
```

#### 设置访问断点的大小

```shell
(gdb) watch *(char *) <address> 
#would set a watchpoint to break on access to the one byte at <address>, and therefore wouldn\'t fire if address+2 was written to. Whereas

(gdb )watch *(long long *) <address>
#would fire if any of the 8 bytes starting at <address> were written to.
```

### 硬件断点

使用"hbreak" 命令 (short form: hb) 用法与break相似

## 检查/修改数据

Commands: x (examine), print, display

格式化输出：
后边跟/nFMT

```md
10.5 Output Formats

By default, GDB prints a value according to its data type. Sometimes this is not what you want. For example, you might want to print a number in hex, or a pointer in decimal. Or you might want to view data in memory at a certain address as a character string or as an instruction. To do these things, specify an output format when you print a value.

The simplest use of output formats is to say how to print a value already computed. This is done by starting the arguments of the print command with a slash and a format letter. The format letters supported are:

x
Regard the bits of the value as an integer, and print the integer in hexadecimal.

d
Print as integer in signed decimal.

u
Print as integer in unsigned decimal.

o
Print as integer in octal.

t
Print as integer in binary. The letter ‘t’ stands for “two”. 11

a
Print as an address, both absolute in hexadecimal and as an offset from the nearest preceding symbol. You can use this format used to discover where (in what function) an unknown address is located:

(gdb) p/a 0x54320
$3 = 0x54320 <_initialize_vx+396>
The command info symbol 0x54320 yields similar results. See info symbol.

c
Regard as an integer and print it as a character constant. This prints both the numerical value and its character representation. The character representation is replaced with the octal escape ‘\nnn’ for characters outside the 7-bit ASCII range.

Without this format, GDB displays char, unsigned char, and signed char data as character constants. Single-byte members of vectors are displayed as integer data.

f
Regard the bits of the value as a floating point number and print using typical floating point syntax.

s
Regard as a string, if possible. With this format, pointers to single-byte data are displayed as null-terminated strings and arrays of single-byte data are displayed as fixed-length strings. Other values are displayed in their natural types.

Without this format, GDB displays pointers to and arrays of char, unsigned char, and signed char as strings. Single-byte members of a vector are displayed as an integer array.

z
Like ‘x’ formatting, the value is treated as an integer and printed as hexadecimal, but leading zeros are printed to pad the value to the size of the integer type.

r
Print using the ‘raw’ formatting. By default, GDB will use a Python-based pretty-printer, if one is available (see Pretty Printing). This typically results in a higher-level display of the value’s contents. The ‘r’ format bypasses any Python pretty-printer which might exist.

For example, to print the program counter in hex (see Registers), type

p/x $pc
Note that no space is required before the slash; this is because command names in GDB cannot contain a slash.

To reprint the last value in the value history with a different format, you can use the print command with just a format and no expression. For example, ‘p/x’ reprints the last value in hex.
```

[FMT](https://sourceware.org/gdb/onlinedocs/gdb/Output-Formats.html)

### 检查寄存器

info r rax rbx rbp

也可以使用print(short form:p)结合/FMT，进行格式化输出

### 修改寄存器

```shell
(gdb) set $rax = 0xdeadbeeff00dface
(gdb) p/x $rax
$15 = 0xdeadbeeff00dface
(gdb) set $ax = 0xcafef00d
(gdb) p/x $rax
$16 = 0xdeadbeeff00df00d
```

### 检查内存

```shell
#The "x" command (for examine memory) supports the /FMT specifier.
(gdb) x/8xb $rsp
0x7fffffffe038: 0xb3 0xd0 0xde 0xf7 0xff 0x7f 0x00 0x00
(gdb) x/4xh $rsp
0x7fffffffe038: 0xd0b3 0xf7de 0x7fff 0x0000
(gdb) x/2xw $rsp
0x7fffffffe038: 0xf7ded0b3 0x00007fff
(gdb) x/1xg $rsp
0x7fffffffe038: 0x00007ffff7ded0b3
(gdb) x/s 0x555555556008
0x555555556008: "First %d elements of the Fibbonacci sequence: "
(gdb) x/3i $rip
=> 0x5555555551a9 <main>: endbr64 
   0x5555555551ad <main+4>: push   %rbp
   0x5555555551ae <main+5>: mov    %rsp,%rbp
```

### 修改内存

```shell
 (gdb) x/1xg $rsp
0x7fffffffe038: 0x00007ffff7ded0b3
(gdb) set {char}$rsp = 0xFF
(gdb) x/1xg $rsp
0x7fffffffe038: 0x00007ffff7ded0ff
(gdb) set {short}$rsp = 0xFF
(gdb) x/1xg $rsp
0x7fffffffe038: 0x00007ffff7de00ff
(gdb) set {short}$rsp = 0xFFFF
(gdb) x/1xg $rsp
0x7fffffffe038: 0x00007ffff7deffff
(gdb) set {long long}$rsp = 0x1337bee7
(gdb) x/1xg $rsp
0x7fffffffe038: 0x000000001337bee7
```

### 栈回溯

[bt](https://sourceware.org/gdb/current/onlinedocs/gdb/Backtrace.html#Backtrace)

## 五、单步运行

单步步过：ni
单步步入：si
单步步出：finish(short form:fin)

运行到某个地址：until \<address\>

## 六、附加运行

依赖于你的系统安全设置支不支持ptrace的系统调用，你也许不能附加到进程上，尽管你们使用的是相同的用户。你也可以使用root权限运行gdb，或者使用下述命令去禁用掉这个安全选项。

```shell
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

Remembering to re-restrict access when done via:

```shell
echo 1 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

attach \<process ID\>

## 七、杂项配置

可以在gdb中使用下述命令修改gdb的汇编语言的类型到Intel或者AT&T：

set disassembly-flavor intel
set disassembly-flavor att

## 八、gdb的命令行文件

有时候想要让他在启动gdb时就自动运行一些命令，可以使用脚本，gdb启动时加上 -x 指定脚本文件 就可以了。
