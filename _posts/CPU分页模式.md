---
title: 分页模式开启
date: 2021-07-05
tags: CPU
---

## MMU

设置 CPU 的 CR0 的 PE 位为 1，这样就开启了 MMU。

```assembly
mov eax, PAGE_TLB_BADR ;页表物理地址
mov cr3, eax
;开启 保护模式和分页模式
mov eax, cr0
bts eax, 0 ;CR0.PE =1
bts eax, 31 ;CR0.P = 1
mov cr0, eax
```
