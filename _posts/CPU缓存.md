---
title: CPU缓存
date: 2021-07-05
tags: CPU
---

## MESI协议

MESI 协议定义了 4 种基本状态：M、E、S、I，即修改（Modified）、独占（Exclusive）、共享（Shared）和无效（Invalid）。

1.M 修改（Modified）：当前 Cache 的内容有效，数据已经被修改而且与内存中的数据不一致，数据只在当前 Cache 里存在。

2.E 独占（Exclusive）：当前 Cache 中的内容有效，数据与内存中的数据一致，数据只在当前 Cache 里存在。

3.S 共享（Shared）：当前 Cache 中的内容有效，Cache 中的数据与内存中的数据一致，数据在多个 CPU 核心中的 Cache 里面存在。

4.无效（Invalid）：当前 Cache 无效。

Cache 硬件，它会监控所有 CPU 上 Cache 的操作，根据相应的操作使得 Cache 里的数据行在上面这些状态之间切换。Cache 硬件通过这些状态的变化，就能安全地控制各 Cache 间、各 Cache 与内存之间的数据一致性了。

## 开启 Cache

在 x86 CPU 上开启 Cache 非常简单，只需要将 CR0 寄存器中 CD、NW 位同时清 0 即可。CD=1 时表示 Cache 关闭，NW=1 时 CPU 不维护内存数据一致性。

```assembly
mov eax, cr0
;开启 CACHE    
btr eax,29 ;CR0.NW=0
btr eax,30  ;CR0.CD=0
mov cr0, eax
```

## 获取内存视图

给出一个物理地址并不能准确地定位到内存空间，内存空间只是映射物理地址空间中的一个子集，物理地址空间中可能有空洞，有 ROM，有内存，有显存，有 I/O 寄存器，所以获取内存有多大没用，关键是要获取哪些物理地址空间是可以读写的内存。

物理地址空间是由北桥芯片控制管理的，那我们是不是要找北桥要内存的地址空间呢？当然不是，在 x86 平台上还有更方便简单的办法，那就是 BIOS 提供的实模式下中断服务，就是 int 指令后面跟着一个常数的形式。由于 PC 机上电后由 BIOS 执行硬件初始化，中断向量表是 BIOS 设置的，所以执行中断自然执行 BIOS 服务。这个中断服务是 int 15h，但是它需要一些参数，就是在执行 int 15h 之前，对特定寄存器设置一些值，代码如下。

```assembly
_getmemmap:  
    xor ebx,ebx ;ebx设为0  
    mov edi,E80MAP_ADR ;edi设为存放输出结果的1MB内的物理内存
loop:  
    mov eax,0e820h ;eax必须为0e820h  
    mov ecx,20 ;输出结果数据项的大小为20字节：8字节内存基地址，8字节内存长度，4字节内存类型  
    mov edx,0534d4150h ;edx必须为0534d4150h  
    int 15h ;执行中断  
    jc error ;如果flags寄存器的C位置1，则表示出错  
    add edi,20;更新下一次输出结果的地址  
    cmp ebx,0 ;如ebx为0，则表示循环迭代结束  
    jne loop  ;还有结果项，继续迭代    
    ret
error:;出错处理
```

```c
#define RAM_USABLE 1 //可用内存
#define RAM_RESERV 2 //保留内存不可使用
#define RAM_ACPIREC 3 //ACPI表相关的
#define RAM_ACPINVS 4 //ACPI NVS空间
#define RAM_AREACON 5 //包含坏内存
typedef struct s_e820{    
    u64_t saddr;    /* 内存开始地址 */    
    u64_t lsize;    /* 内存大小 */    
    u32_t type;    /* 内存类型 */
}e820map_t;
```
