---
title: CPU实模式和保护模式
date: 2021-07-04
tags: CPU
---

## 实模式

实模式又称实地址模式，对内存不加以任何的限制。

### 实模式的寄存器

x86CPU在实模式下的寄存器都是16位的。

| 寄存器 | 描述 |
| ---- | ---- |
| AX、BX、CX、DX、DI、SI、BP  | 通用寄存器，里面可以存放数据、地址、参与运算 |
| IP  | 程序指针寄存器，始终指向下一条指令的地址 |
| SP  | 栈指针寄存器，始终指向当前栈顶 |
| CS、DS、ES、SS  | 段寄存器，里面存放一个内存段的基地址 |
| FLAGS  | 标志寄存器  |

### 实模式下访问内存

实模式下所有的内存地址都是由段寄存器左移 4 位，再加上一个通用寄存器中的值或者常数形成地址，然后由这个地址去访问内存。

### 实模式中断

中断即中止执行当前程序，转而跳转到另一个特定的地址上，去运行特定的代码。在实模式下它的实现过程是先保存 CS 和 IP 寄存器，然后装载新的 CS 和 IP 寄存器。

通过IDTR查找中断向量表，根据中断号索引中断处理的地址。

## 保护模式

### 保护模式寄存器

保护模式相比于实模式，增加了一些控制寄存器和段寄存器，扩展通用寄存器的位宽，所有的通用寄存器都是 32 位的，还可以单独使用低 16 位，这个低 16 位又可以拆分成两个 8 位寄存器，

| 寄存器 | 描述 |
| ---- | ---- |
| EAX、EBX、ECX、EDX、EDI、ESI、EBP  | 通用寄存器，里面可以存放数据、地址、参与运算 |
| EIP  | 程序指针寄存器，始终指向下一条指令的地址 |
| ESP  | 栈指针寄存器，始终指向当前栈顶 |
| CS、DS、ES、SS、FS、GS  | 段寄存器，里面存放一个内存段的基地址 |
| EFLAGS  | 标志寄存器  |
| CRO、CR1、CR2、CR3 | CPU控制寄存器，控制CPU的功能特性 |

### 保护模式特权级

特权级分为4级R0～R3

### 切换到保护模式

段描述符：

```nasm
GDT_START:
knull_dsc: dq 0
;第一个段描述符CPU硬件规定必须为0
kcode_dsc: dq 0x00cf9e000000ffff
;段基地址=0，段长度=0xfffff
;G=1,D/B=1,L=0,AVL=0 
;P=1,DPL=0,S=1
;T=1,C=1,R=1,A=0
kdata_dsc: dq 0x00cf92000000ffff
;段基地址=0，段长度=0xfffff
;G=1,D/B=1,L=0,AVL=0 
;P=1,DPL=0,S=1
;T=0,C=0,R=1,A=0
GDT_END:

GDT_PTR:
GDTLEN  dw GDT_END-GDT_START-1
GDTBASE  dd GDT_START
```

1、准备全局段描述符

```nasm
GDT_START:knull_dsc: dq 0kcode_dsc: dq 0x00cf9e000000ffffkdata_dsc: dq 0x00cf92000000ffffGDT_END:GDT_PTR:GDTLEN  dw GDT_END-GDT_START-1GDTBASE  dd GDT_START
```

2、加载gdtr寄存器

```nasm
lgdt [GDT_PTR]
```

3、设置 CR0 寄存器，开启保护模式。

```nasm
;开启 PE
mov eax, cr0
bts eax, 0                      ; CR0.PE =1
mov cr0, eax         
```

4、进行长跳转，加载 CS 段寄存器，即段选择子。

```nasm
jmp dword 0x8 :_32bits_mode ;_32bits_mode为32位代码标号即段偏移
```
