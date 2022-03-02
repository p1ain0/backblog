---
title: unicorn分析
date: 2021-11-13 17:54:20
tags:
---

## unicorn简介

unicorn是一个轻量级，多平台，多架构的CPU模拟器框架，支持多种CPU架构，支持windows和linux，提供的API接口简洁易用。使用JIT编译技术，性能表现优异。unicorn是基于qemu而开发的，裁剪了qemu的CPU模拟部分。qemu的TCG机制保证了unicorn具有跨平台优点。

## unicorn API

### 内存映射/反映射

```C++
uc_err uc_mem_map(uc_engine* uc, uint64_t address, size_t size, uint32_t perms);
uc_err uc_mem_unmap(uc_engine* uc, uint64_t address, size_t size);
```

### 内存读写

```c++
uc_err uc_mem_read(uc_engine* uc, uint64_t address, void* bytes, size_t size);
uc_err uc_mem_write(uc_engine* uc, uint64_t address, const void* bytes, size_t size);
```

### 寄存器读写

```c++
uc_err uc_reg_read(un_engine* uc, int regid, void* value);
uc_err uc_reg_write(un_engine* uc, int regid, const void* value);
```

### 指令回调

```c++
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, ...);
uc_err uc_hook_del(uc_engine *uc, uc_hook hh);
```

### 打开启动停止

```c++
uc_err uc_open(uc_arch arch, uc_mode mode, uc_engine **uc);
uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);
uc_err uc_emu_stop(uc_engine *uc);
```

## unicorn使用流程

初始化unicorn接口 -> 初始化平台信息 -> 映射虚拟机物理内存 -> 设置虚拟机寄存器组 -> 设置相应的指令回调函数（HOOK_CODE每条指令 HOOK_BLOCK每个指令块 HOOK_INTR int n和syscall执行时回调 HOOK_INSN 特定指令执行时回调） -> 开始模拟执行
