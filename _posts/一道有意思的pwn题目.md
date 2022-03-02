---
title: 记一道有意思的ctf题目
date: 2021-07-03
tags: CTF
---

原题目是pwnable.tw上边的calc，数组越界读写类的题目，

解题过程：首先通过越界读和printf把ebp泄漏出来，可以得到栈地址的信息，然后将rop写到retaddr处，利用ROPgadget寻找rop的地址，利用泄漏的栈地址计算当前栈的位置，把"/bin/sh"写到栈空间上的地址，也写到rop链中，并利用pop ebx,把地址保存到ebx中。实现 int 0x80系统调用。

(PS:漏洞利用点是看网上大神的题解才知道的)
