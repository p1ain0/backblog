---
title: Windows系统调用
date: 2021-09-24 21:55:29
tags: windows内核
---

## 逆向分析目标

主要分析windows系统调用问题的下列四个问题：

    (1)程序进入0环后，原来3环的寄存器会保存到什么地方？
    (2)如何根据系统服务号找到要执行的内核函数？
    (3)调用时参数是如何传递给内核函数的？
    (4)如何返回3环？

## 分析过程

### 应用层过程分析

首先在ntdll中找到一个目标函数。我这找的是`ZwProtectVirtualMemory`。函数详情如下：

```assembly

.text:7C92D6D0 ; __stdcall ZwProtectVirtualMemory(x, x, x, x, x)
.text:7C92D6D0                 public _ZwProtectVirtualMemory@20
.text:7C92D6D0 _ZwProtectVirtualMemory@20 proc near    ; CODE XREF: LdrpSnapIAT(x,x,x,x)+64↓p
.text:7C92D6D0                                         ; LdrpSnapIAT(x,x,x,x)+101↓p ...
.text:7C92D6D0                 mov     eax, 89h ; '‰'  ; NtProtectVirtualMemory
.text:7C92D6D5                 mov     edx, 7FFE0300h
.text:7C92D6DA                 call    dword ptr [edx]
.text:7C92D6DC                 retn    14h
.text:7C92D6DC _ZwProtectVirtualMemory@20 endp
```

Windbg中信息如下，

```assembly

kd> u ntdll!ZwProtectVirtualMemory
ntdll!ZwProtectVirtualMemory:
7c92d6d0 b889000000      mov     eax,89h
7c92d6d5 ba0003fe7f      mov     edx,offset SharedUserData!SystemCallStub (7ffe0300)
7c92d6da ff12            call    dword ptr [edx]
7c92d6dc c21400          ret     14h
7c92d6df 90              nop

```

函数就干了两件事情，将**89h**调用号存入**eax**寄存器中，调用7FFE0300h地址存的函数的地址。这个地址就是user层进入kernel层的关键，在详细说明这个地址之前我们要先介绍一个结构体`_KUSER_SHARED_DATA`。

```

kd> dt _KUSER_SHARED_DATA 7ffe0000
ntdll!_KUSER_SHARED_DATA
   +0x000 TickCountLow     : 0x36237
   +0x004 TickCountMultiplier : 0xfa00000
   +0x008 InterruptTime    : _KSYSTEM_TIME
   +0x014 SystemTime       : _KSYSTEM_TIME
   +0x020 TimeZoneBias     : _KSYSTEM_TIME
   +0x02c ImageNumberLow   : 0x14c
   +0x02e ImageNumberHigh  : 0x14c
   +0x030 NtSystemRoot     : [260] 0x43
   +0x238 MaxStackTraceDepth : 0
   +0x23c CryptoExponent   : 0
   +0x240 TimeZoneId       : 0
   +0x244 Reserved2        : [8] 0
   +0x264 NtProductType    : 1 ( NtProductWinNt )
   +0x268 ProductTypeIsValid : 0x1 ''
   +0x26c NtMajorVersion   : 5
   +0x270 NtMinorVersion   : 1
   +0x274 ProcessorFeatures : [64]  ""
   +0x2b4 Reserved1        : 0x7ffeffff
   +0x2b8 Reserved3        : 0x80000000
   +0x2bc TimeSlip         : 0
   +0x2c0 AlternativeArchitecture : 0 ( StandardDesign )
   +0x2c8 SystemExpirationDate : _LARGE_INTEGER 0x0
   +0x2d0 SuiteMask        : 0x110
   +0x2d4 KdDebuggerEnabled : 0x3 ''
   +0x2d5 NXSupportPolicy  : 0x2 ''
   +0x2d8 ActiveConsoleId  : 0
   +0x2dc DismountCount    : 0
   +0x2e0 ComPlusPackage   : 0xffffffff
   +0x2e4 LastSystemRITEventTickCount : 0x348ba9
   +0x2e8 NumberOfPhysicalPages : 0x1ff6c
   +0x2ec SafeBootMode     : 0 ''
   +0x2f0 TraceLogging     : 0
   +0x2f8 TestRetInstruction : 0xc3
   +0x300 SystemCall       : 0x7c92e4f0
   +0x304 SystemCallReturn : 0x7c92e4f4
   +0x308 SystemCallPad    : [3] 0
   +0x320 TickCount        : _KSYSTEM_TIME
   +0x320 TickCountQuad    : 0
   +0x330 Cookie           : 0x55a2fab8
```

在 User 层和 Kernel 层分别定义了一个 _KUSER_SHARED_DATA 结构区域，用于 User 层和 Kernel 层共享某些数据
它们使用固定的地址值映射，_KUSER_SHARED_DATA 结构区域在 User 和 Kernel 层地址分别为：
User 层地址为：0x7ffe0000
Kernnel 层地址为：0xffdf0000
通过winbdg查看，可以发现user层地址0x7ffe0000 和kernel层地址0xffdf0000的内容是一样的，虽然指向的是同一个物理页，但在User 层是只读的，在Kernnel层是可写的。

如果cpu支持快速调用，7FFE0300h地址处保存的函数地址是ntdll.dll!KiFastSystemCall()。如果cpu不支持快速调用，那么保存的函数地址是ntdll.dll!KiIntSystemCall()。

如果你的系统不支持快速调用，那么可以使用`!idt -a`找到0x2E中断描述符的调用地址。

```assembly

kd> !idt -a

Dumping IDT: 8003f400
...
2e:	8053e481 nt!KiSystemService
...
```

如果你的系统支持快速调用，可以通过查询msr寄存器的方式获取进内核的入口函数地址。如下所示：`0x8053e540`便是我们要查询到的函数（nt!KiFastCallEntry）
地址了。

```assembly

kd> rdmsr 174 
msr[174] = 00000000`00000008 ;cs
kd> rdmsr 175
msr[175] = 00000000`f8ac2000 ;esp
kd> rdmsr 176
msr[176] = 00000000`8053e540 ;eip
```

### 内核层调用分析

在分析内核层的调用过程前，我们需要看几个结构体，

```assembly

kd> dt _KTrap_Frame
nt!_KTRAP_FRAME
   +0x000 DbgEbp           : Uint4B
   +0x004 DbgEip           : Uint4B
   +0x008 DbgArgMark       : Uint4B
   +0x00c DbgArgPointer    : Uint4B
   +0x010 TempSegCs        : Uint4B
   +0x014 TempEsp          : Uint4B
   +0x018 Dr0              : Uint4B
   +0x01c Dr1              : Uint4B
   +0x020 Dr2              : Uint4B
   +0x024 Dr3              : Uint4B
   +0x028 Dr6              : Uint4B
   +0x02c Dr7              : Uint4B
   +0x030 SegGs            : Uint4B
   +0x034 SegEs            : Uint4B
   +0x038 SegDs            : Uint4B
   +0x03c Edx              : Uint4B
   +0x040 Ecx              : Uint4B
   +0x044 Eax              : Uint4B
   +0x048 PreviousPreviousMode : Uint4B
   +0x04c ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD
   +0x050 SegFs            : Uint4B
   +0x054 Edi              : Uint4B
   +0x058 Esi              : Uint4B
   +0x05c Ebx              : Uint4B
   +0x060 Ebp              : Uint4B
   +0x064 ErrCode          : Uint4B
   +0x068 Eip              : Uint4B
   +0x06c SegCs            : Uint4B
   +0x070 EFlags           : Uint4B
   +0x074 HardwareEsp      : Uint4B
   +0x078 HardwareSegSs    : Uint4B
   +0x07c V86Es            : Uint4B
   +0x080 V86Ds            : Uint4B
   +0x084 V86Fs            : Uint4B
   +0x088 V86Gs            : Uint4B
```

```assembly

kd> dt _KPCR
nt!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x01c SelfPcr          : Ptr32 _KPCR
   +0x020 Prcb             : Ptr32 _KPRCB
   +0x024 Irql             : UChar
   +0x028 IRR              : Uint4B
   +0x02c IrrActive        : Uint4B
   +0x030 IDR              : Uint4B
   +0x034 KdVersionBlock   : Ptr32 Void
   +0x038 IDT              : Ptr32 _KIDTENTRY
   +0x03c GDT              : Ptr32 _KGDTENTRY
   +0x040 TSS              : Ptr32 _KTSS
   +0x044 MajorVersion     : Uint2B
   +0x046 MinorVersion     : Uint2B
   +0x048 SetMember        : Uint4B
   +0x04c StallScaleFactor : Uint4B
   +0x050 DebugActive      : UChar
   +0x051 Number           : UChar
   +0x052 Spare0           : UChar
   +0x053 SecondLevelCacheAssociativity : UChar
   +0x054 VdmAlert         : Uint4B
   +0x058 KernelReserved   : [14] Uint4B
   +0x090 SecondLevelCacheSize : Uint4B
   +0x094 HalReserved      : [16] Uint4B
   +0x0d4 InterruptMode    : Uint4B
   +0x0d8 Spare1           : UChar
   +0x0dc KernelReserved2  : [17] Uint4B
   +0x120 PrcbData         : _KPRCB
```

```assembly

kd> dt _ETHREAD
nt!_ETHREAD
   +0x000 Tcb              : _KTHREAD
   +0x1c0 CreateTime       : _LARGE_INTEGER
   +0x1c0 NestedFaultCount : Pos 0, 2 Bits
   +0x1c0 ApcNeeded        : Pos 2, 1 Bit
   +0x1c8 ExitTime         : _LARGE_INTEGER
   +0x1c8 LpcReplyChain    : _LIST_ENTRY
   +0x1c8 KeyedWaitChain   : _LIST_ENTRY
   +0x1d0 ExitStatus       : Int4B
   +0x1d0 OfsChain         : Ptr32 Void
   +0x1d4 PostBlockList    : _LIST_ENTRY
   +0x1dc TerminationPort  : Ptr32 _TERMINATION_PORT
   +0x1dc ReaperLink       : Ptr32 _ETHREAD
   +0x1dc KeyedWaitValue   : Ptr32 Void
   +0x1e0 ActiveTimerListLock : Uint4B
   +0x1e4 ActiveTimerListHead : _LIST_ENTRY
   +0x1ec Cid              : _CLIENT_ID
   +0x1f4 LpcReplySemaphore : _KSEMAPHORE
   +0x1f4 KeyedWaitSemaphore : _KSEMAPHORE
   +0x208 LpcReplyMessage  : Ptr32 Void
   +0x208 LpcWaitingOnPort : Ptr32 Void
   +0x20c ImpersonationInfo : Ptr32 _PS_IMPERSONATION_INFORMATION
   +0x210 IrpList          : _LIST_ENTRY
   +0x218 TopLevelIrp      : Uint4B
   +0x21c DeviceToVerify   : Ptr32 _DEVICE_OBJECT
   +0x220 ThreadsProcess   : Ptr32 _EPROCESS
   +0x224 StartAddress     : Ptr32 Void
   +0x228 Win32StartAddress : Ptr32 Void
   +0x228 LpcReceivedMessageId : Uint4B
   +0x22c ThreadListEntry  : _LIST_ENTRY
   +0x234 RundownProtect   : _EX_RUNDOWN_REF
   +0x238 ThreadLock       : _EX_PUSH_LOCK
   +0x23c LpcReplyMessageId : Uint4B
   +0x240 ReadClusterSize  : Uint4B
   +0x244 GrantedAccess    : Uint4B
   +0x248 CrossThreadFlags : Uint4B
   +0x248 Terminated       : Pos 0, 1 Bit
   +0x248 DeadThread       : Pos 1, 1 Bit
   +0x248 HideFromDebugger : Pos 2, 1 Bit
   +0x248 ActiveImpersonationInfo : Pos 3, 1 Bit
   +0x248 SystemThread     : Pos 4, 1 Bit
   +0x248 HardErrorsAreDisabled : Pos 5, 1 Bit
   +0x248 BreakOnTermination : Pos 6, 1 Bit
   +0x248 SkipCreationMsg  : Pos 7, 1 Bit
   +0x248 SkipTerminationMsg : Pos 8, 1 Bit
   +0x24c SameThreadPassiveFlags : Uint4B
   +0x24c ActiveExWorker   : Pos 0, 1 Bit
   +0x24c ExWorkerCanWaitUser : Pos 1, 1 Bit
   +0x24c MemoryMaker      : Pos 2, 1 Bit
   +0x250 SameThreadApcFlags : Uint4B
   +0x250 LpcReceivedMsgIdValid : Pos 0, 1 Bit
   +0x250 LpcExitThreadCalled : Pos 1, 1 Bit
   +0x250 AddressSpaceOwner : Pos 2, 1 Bit
   +0x254 ForwardClusterOnly : UChar
   +0x255 DisablePageFaultClustering : UChar
```

非快速系统调用如下：
```assembly

.text:8053E481 ; int __usercall KiSystemService@<eax>(int@<edx>, int@<ebx>, int@<ebp>, int@<edi>, int@<esi>, char)
.text:8053E481 _KiSystemService proc near              ; CODE XREF: ZwAcceptConnectPort(x,x,x,x,x,x)+C↑p
.text:8053E481                                         ; ZwAccessCheck(x,x,x,x,x,x,x,x)+C↑p ...
.text:8053E481
.text:8053E481 arg_0           = dword ptr  4
.text:8053E481
.text:8053E481                 push    0               ; KTrap_Frame+0x64,ErrorCode
.text:8053E483                 push    ebp
.text:8053E484                 push    ebx
.text:8053E485                 push    esi
.text:8053E486                 push    edi
.text:8053E487                 push    fs
.text:8053E489                 mov     ebx, 30h ; '0'  ; 为fs赋值，指向KPCR结构体
.text:8053E48E                 mov     fs, bx
.text:8053E491                 assume fs:nothing
.text:8053E491                 push    dword ptr ds:0FFDFF000h ; 保存老的ExceptionList
.text:8053E497                 mov     dword ptr ds:0FFDFF000h, 0FFFFFFFFh
.text:8053E4A1                 mov     esi, ds:0FFDFF124h ; 得到当前线程的执行信息，是一个_KTHREAD结构体。
.text:8053E4A7                 push    dword ptr [esi+140h] ; 保存以前的PreviousMode
.text:8053E4AD                 sub     esp, 48h        ; esp指向_KTrap_Frame
.text:8053E4B0                 mov     ebx, [esp+6Ch]  ; 系统调用前的CS寄存器的值
.text:8053E4B4                 and     ebx, 1          ; 0环是0，三环是1
.text:8053E4B7                 mov     [esi+140h], bl  ; 结果保存到PreviousMode里
.text:8053E4BD                 mov     ebp, esp        ; ebp指向_KTrap_Frame
.text:8053E4BF                 mov     ebx, [esi+134h] ; 取出以前的KTrap_Frame
.text:8053E4C5                 mov     [ebp+3Ch], ebx  ; 暂存到KTrap_Frame结构体的edx位置处
.text:8053E4C8                 mov     [esi+134h], ebp ; 保存新的_KTrap_Frame
.text:8053E4CE                 cld
.text:8053E4CF                 mov     ebx, [ebp+60h]  ; 3环的ebp
.text:8053E4D2                 mov     edi, [ebp+68h]  ; 3环的eip
.text:8053E4D5                 mov     [ebp+0Ch], edx  ; edx存的是三环参数指针
.text:8053E4D8                 mov     dword ptr [ebp+8], 0BADB0D00h
.text:8053E4DF                 mov     [ebp+0], ebx    ; 3环的ebp存到+0x000 DbgEbp: Uint4B
.text:8053E4E2                 mov     [ebp+4], edi    ; 3环的eip存到+0x004 DbgEip: Uint4B
.text:8053E4E5                 test    byte ptr [esi+2Ch], 0FFh ; 判断_KTHREAD的DebugActive，是否为-1，检查是否处于调试状态
.text:8053E4E9                 jnz     Dr_kss_a
.text:8053E4EF
.text:8053E4EF loc_8053E4EF:                           ; CODE XREF: Dr_kss_a+10↑j
.text:8053E4EF                                         ; Dr_kss_a+7C↑j
.text:8053E4EF                 sti
.text:8053E4F0                 jmp     loc_8053E5CD
```

查找系统服务的过程如下：

```assembly

loc_8053E5CD:                           ; CODE XREF: _KiBBTUnexpectedRange+18↑j
.text:8053E5CD                                         ; _KiSystemService+6F↑j
.text:8053E5CD                 mov     edi, eax        ; eax是系统调用号
.text:8053E5CF                 shr     edi, 8          ; 右移8位
.text:8053E5D2                 and     edi, 30h        ; 检测第12位是否为1
.text:8053E5D5                 mov     ecx, edi        ; ecx为Service类型的索引
.text:8053E5D7                 add     edi, [esi+0E0h] ; KTHREAD->ServiceTable
.text:8053E5DD                 mov     ebx, eax
.text:8053E5DF                 and     eax, 0FFFh      ; 系统调用号只要后12位做索引
.text:8053E5E4                 cmp     eax, [edi+8]    ; typedef struct _SYSTEM_SERVICE_TABLE{
.text:8053E5E4                                         ; PVOID ServiceTableBase;    //系统服务函数地址表
.text:8053E5E4                                         ; PULONG ServiceCounterTableBase;
.text:8053E5E4                                         ; ULONG NumberOfService;//服务函数的个数
.text:8053E5E4                                         ; ULONG ParamTableBase;//参数表基址
.text:8053E5E4                                         ; }
.text:8053E5E7                 jnb     _KiBBTUnexpectedRange
.text:8053E5ED                 cmp     ecx, 10h
.text:8053E5F0                 jnz     short loc_8053E60C ; KPCR->+0x518增加1
.text:8053E5F2                 mov     ecx, ds:0FFDFF018h
.text:8053E5F8                 xor     ebx, ebx
.text:8053E5FA
.text:8053E5FA loc_8053E5FA:                           ; DATA XREF: _KiTrap0E+113↓o
.text:8053E5FA                 or      ebx, [ecx+0F70h]
.text:8053E600                 jz      short loc_8053E60C ; KPCR->+0x518增加1
.text:8053E602                 push    edx
.text:8053E603                 push    eax
.text:8053E604                 call    ds:_KeGdiFlushUserBatch
.text:8053E60A                 pop     eax
.text:8053E60B                 pop     edx
.text:8053E60C
.text:8053E60C loc_8053E60C:                           ; CODE XREF: _KiFastCallEntry+B0↑j
.text:8053E60C                                         ; _KiFastCallEntry+C0↑j
.text:8053E60C                 inc     dword ptr ds:0FFDFF638h ; KPCR->+0x518增加1
.text:8053E612                 mov     esi, edx        ; edx存着3环参数指针
.text:8053E614                 mov     ebx, [edi+0Ch]  ; 参数表基址
.text:8053E617                 xor     ecx, ecx
.text:8053E619                 mov     cl, [eax+ebx]   ; 参数表+调用号得到参数的个数
.text:8053E61C                 mov     edi, [edi]      ; 系统服务地址表
.text:8053E61E                 mov     ebx, [edi+eax*4] ; ebx调用函数的地址
.text:8053E621                 sub     esp, ecx        ; 提升栈空间，保存参数用的
.text:8053E623                 shr     ecx, 2
.text:8053E626                 mov     edi, esp
.text:8053E628                 cmp     esi, ds:_MmUserProbeAddress
.text:8053E62E                 jnb     loc_8053E7DC
.text:8053E634
.text:8053E634 loc_8053E634:                           ; CODE XREF: _KiFastCallEntry+2A0↓j
.text:8053E634                                         ; DATA XREF: _KiTrap0E+109↓o
.text:8053E634                 rep movsd               ; copy执行
.text:8053E636                 call    ebx             ; 执行目标函数
```

查看SSDT的方式：

```assembly
dd KeServiceDescriptorTable
dd KeServiceDescriptorTableShadow
```
