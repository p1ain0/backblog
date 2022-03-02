---
title: Windows内核对象
date: 2020-03-30
tags: windows内核
---

## Windows内核对象管理

**Windows对象管理器的基本设计意图是：**

-​ 为执行体的数据结构提供一种统一而又可扩展的定义和控制机制。

​- 提供统一的安全访问机制。

​- 在无须修改已有系统代码的情况下，加入新的对象类型。

​- 提供一组标准的API来对对象执行各种操作。

​- 提供一种命名机制，与文件系统的命名机制集成在一起。

每一个对象由两部分构成：对象头和对象体。所有对象的对象头都具有统一的格式，其定义如下：

```c
typedef struct _OBJECT_CREATE_INFORMATION *POBJECT_CREATE_INFORMATION;;

typedef struct _OBJECT_HEADER {
    LONG_PTR PointerCount;                        //引用计数
    union {
        LONG_PTR HandleCount;                    //指向该对象的句柄数
        PVOID NextToFree;                        //对象被延迟删除时加入到一条链中
    };
    POBJECT_TYPE Type;                            //指向对象的类型对象
    UCHAR NameInfoOffset;                        //名称信息的内存偏移
    UCHAR HandleInfoOffset;                        //句柄信息的内存偏移
    UCHAR QuotaInfoOffset;                        //配额信息的内存偏移
    UCHAR Flags;

    union {
        POBJECT_CREATE_INFORMATION ObjectCreateInfo;
        PVOID QuotaBlockCharged;
    };

    PSECURITY_DESCRIPTOR SecurityDescriptor;    //安全描述符
    QUAD Body;                                    //对象体开始
} OBJECT_HEADER, *POBJECT_HEADER;

```

```c
kd> dt _OBJECT_HEADER
nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int4B
   +0x004 HandleCount      : Int4B
   +0x004 NextToFree       : Ptr32 Void
   +0x008 Type             : Ptr32 _OBJECT_TYPE
   +0x00c NameInfoOffset   : UChar
   +0x00d HandleInfoOffset : UChar
   +0x00e QuotaInfoOffset  : UChar
   +0x00f Flags            : UChar
   +0x010 ObjectCreateInfo : Ptr32 _OBJECT_CREATE_INFORMATION
   +0x010 QuotaBlockCharged : Ptr32 Void
   +0x014 SecurityDescriptor : Ptr32 Void
   +0x018 Body             : _QUAD
```

**对象头包含了对象管理所需的基本信息，在Windows中，每一种对象都需要有一个对应的类型对象（OBJECT_TYPE对象），其定义为：**

```c
#define OBJECT_LOCK_COUNT 4

typedef struct _OBJECT_TYPE {
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;            // Copy from object header for convenience
    PVOID DefaultObject;
    ULONG Index;                    // 此类型对象在全局数组中的索引
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
#ifdef POOL_TAGGING
    ULONG Key;
#endif                                 //POOL_TAGGING
    ERESOURCE ObjectLocks[ OBJECT_LOCK_COUNT ];
} OBJECT_TYPE, *POBJECT_TYPE;

```

```c
kd> dt _OBJECT_TYPE
ntdll!_OBJECT_TYPE
   +0x000 Mutex            : _ERESOURCE
   +0x038 TypeList         : _LIST_ENTRY
   +0x040 Name             : _UNICODE_STRING
   +0x048 DefaultObject    : Ptr32 Void
   +0x04c Index            : Uint4B
   +0x050 TotalNumberOfObjects : Uint4B
   +0x054 TotalNumberOfHandles : Uint4B
   +0x058 HighWaterNumberOfObjects : Uint4B
   +0x05c HighWaterNumberOfHandles : Uint4B
   +0x060 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0ac Key              : Uint4B
   +0x0b0 ObjectLocks      : [4] _ERESOURCE
```

**系统定义的对象种类有限，WRK支持的31种对象，各有哟个全局的POBJECT_TYPE变量指向其类型对象：**

| ObjectType:               |
| ------------------------- |
| CmpKeyObjectType          |
| DbgkDebugObjectType       |
| ExCallbackobjectType      |
| ExDesktopObjectType       |
| ExEventobjectType         |
| ExEventPairObjectType     |
| ExMutantObjectType        |
| ExpKeyedEventObjectType   |
| ExProfileObjectType       |
| ExSemaphoreObjectType     |
| ExTimerObjectType         |
| ExWindowStationObjecType  |
| IoAdapterObjectType       |
| IoCompletionObjectType    |
| IoControllerObjectType    |
| IoDeviceHandlerObjectType |
| IoDeviveObjectType        |
| IoDriverObjectType        |
| LpcPortObjectType         |
| LpcWaitablePortObjectType |
| MmSectionObjectType       |
| ObpDeviceMapObjectType    |
| ObpDirectoryObjectType    |
| ObpSymbolicLinkObjectType |
| ObpTypeobjectType         |
| PsJobType                 |
| PsProcessType             |
| PsThreadType              |
| SeTokenObjectType         |
| WmipGuidObjectType        |

**系统在初始化过程中会调用ObCreateObjectType()函数构建起这种对象类型，以完成相应全局变量的初始化。**

```c
NTSTATS
ObCreateObjectType(
    __in PUNICODE_STRING Typename,
    __in POBJECT_TYPE_INITIALIZER ObjectTypeInitializer,
    __in_opt PSECURITY_DESRIPTOR SecurityDescriptor,
    __out POBJECT_TYPE *ObjectType
);
```

```c
typedef struct _OBJECT_TYPE_INITIALIZER {
    USHORT Length;
    BOOLEAN UseDefaultObject;
    BOOLEAN CaseInsensitive;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    BOOLEAN MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    OB_DUMP_METHOD DumpProcedure;
    OB_OPEN_METHOD OpenProcedure;
    OB_CLOSE_METHOD CloseProcedure;
    OB_DELETE_METHOD DeleteProcedure;
    OB_PARSE_METHOD ParseProcedure;
    OB_SECURITY_METHOD SecurityProcedure;
    OB_QUERYNAME_METHOD QueryNameProcedure;
    OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

```

```c
kd> dt _OBJECT_TYPE_INITIALIZER
ntdll!_OBJECT_TYPE_INITIALIZER
   +0x000 Length           : Uint2B
   +0x002 UseDefaultObject : UChar
   +0x003 CaseInsensitive  : UChar
   +0x004 InvalidAttributes : Uint4B
   +0x008 GenericMapping   : _GENERIC_MAPPING
   +0x018 ValidAccessMask  : Uint4B
   +0x01c SecurityRequired : UChar
   +0x01d MaintainHandleCount : UChar
   +0x01e MaintainTypeList : UChar
   +0x020 PoolType         : _POOL_TYPE
   +0x024 DefaultPagedPoolCharge : Uint4B
   +0x028 DefaultNonPagedPoolCharge : Uint4B
   +0x02c DumpProcedure    : Ptr32     void 
   +0x030 OpenProcedure    : Ptr32     long 
   +0x034 CloseProcedure   : Ptr32     void 
   +0x038 DeleteProcedure  : Ptr32     void 
   +0x03c ParseProcedure   : Ptr32     long 
   +0x040 SecurityProcedure : Ptr32     long 
   +0x044 QueryNameProcedure : Ptr32     long 
   +0x048 OkayToCloseProcedure : Ptr32     unsigned char 
```

调用ObCreateObjectType函数来构建一种新的对象类型时，调用者除了可以指定此种类型对象的一些数据特性外，还可以指定该类型对象的一些基本操作方法。

​系统有一个全局变量ObpObjectTypes数组记录所有已创建的类型，这是个静态数组。一旦对象类型被创建，以后内核代码就可以调用ObCreateObject来创建此种类型的对象了。

```c
NTSTATUS
ObCreateObject(
    __in KPROCESSOR_MODE ProbeMode,
    __in POBJECT_TYPE ObjectType,
    __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
    __in KPROCESSOR_MODE OwnershipMode,
    __inout_opt PVOID ParseContext,
    __in ULONG ObjectBodySize,
    __in ULONG PagedPoolCharge,
    __in ULONG NonPagedPoolCharge,
    __out PVOID *Object
    );

```

该函数返回时，Object输出参数指向对象体起始位置。对象体的格式是特定于某种对象类型的，由相应类型对象的诸多过程来维护。

​对象管理器使用对象头中包含的信息来管理这些对象，在对象头中，除了对象名称和对象类型，另有两个重要的信息：指针计数，它记录了内核引用该对象的次数；句柄计数，它记录了有多少个句柄引用此对象，这些句柄可能出现在不同进程中。

​类型对象并不需要为此种的对象提供所有在OBJECT_TYPE_INITIALIZER定义中出现的方法。对象管理器提供了一些通用的服务，这些通用服务可以应用在任何类型的对象上。

​对象的构造是由两部分来完成的：1.调用ObCreateObject，根据指定的类型对象来完成对象头的初始化，并且按照指定的大小分配对象体的内存；2.完成对象体的初始化。前者可以统一完成，后者不可以，因为各种类型的对象体有自己不同的初始化逻辑。

​    Windows也允许使用名称的方式来管理对象。为了做到这一点，Windows必须维护一套全局的名称查询机制。ObpDirectoryObjectType  类型对像是实现这一机制的关键。

​    Windwos内部维护了一个对象层级目录（即系统全局名字空间），其根目录对象是由全局变量ObpRootDirectoryObject来定义的。在根目录之下，系统内置了一些子目录。在WRK中，通过查询NtCreateDirectoryObject函数被调用的情况，可以看到Callback、ArcName、Device、Driver、FileSystem、KernelObjects、ObjectTypes、GLOBAL??和Security子目录的创建过程。

​    对象管理器提供了一些基本的操作用于在名字空间中插入、查询和删除目录或目录项。例如，

| 函数                    | 操作（以下三个函数都直接在一个子目录中进行操作） |
| ----------------------- | ------------------------------------------------ |
| ObpLookupDirectoryEntry | 在一个指定的目录中查找一个名称                   |
| ObpInsertDirectoryEntry | 把一个对象插入到一个目录中                       |
| ObpDeleteDirectoryEntry | 删除刚刚找到的那一项                             |

| 函数                | 操作                                                     |
| ------------------- | -------------------------------------------------------- |
| ObpLookupObjectName | 可以从指定的目录或根目录，递归地根据名称来找到一个对象。 |

```c
NTSTATUS
ObpLookupObjectName (
    IN HANDLE RootDirectoryHandle,
    IN PUNICODE_STRING ObjectName,
    IN ULONG Attributes,
    IN POBJECT_TYPE ObjectType,
    IN KPROCESSOR_MODE AccessMode,
    IN PVOID ParseContext OPTIONAL,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
    IN PVOID InsertObject OPTIONAL,
    IN OUT PACCESS_STATE AccessState,
    OUT POBP_LOOKUP_CONTEXT LookupContext,
    OUT PVOID *FoundObject
    );
```

**其基本的执行逻辑：**

​    参数检查。

​    如果调用者指定了RootDirectoryHandle参数，则利用此RootDirectory的Parse方法来解析对象名称，直到解析成功或者不成功，或者指示从头解析

​    如果调用者没有指定RootDirectoryHandle参数，则系统从全局的根目录ObpRootDirectoryObject开始解析。在这种情况下，传递进来的对象名称必须以“\”开始。如果待查找的名称仅仅是“\”，则执行特殊处理。否则，执行：    

​        1.首先判断名称是否以“\??\”打头，如果是的话，就需要拿到当前进程的DeviceMap（设备表），以进一步查询。

​        2.如果名称正好是"\??"，则直接返回当前进程的DeviceMap作为结果。（DeviceMap定义了一个DOS设备的名字空间，比如驱动器字母C: D:）和一些外设（如COM1）。当对象管理器看到一个以“\??\”打头的名称或者像“\??”这样的名称，它会利用进程的DeviceMap来获得相应的对象目录，然后进一步解析剩余的名称字符串。）

​        3.调用ObpLookupDirectoryEntry函数，层层递进，或者碰到具有Parse方法的对象，由它来解析余下的名称字符串，或者碰到子目录对象，从而可以在子目录对象中进一步查询下一级名称。



​    对象管理器的两个接口函数：ObOpenObjectByName和ObReferenceObjectByName，正是通过ObpLookupObjectName来完成其打开对象或引用对象的功能的。ObInsertObject，它的作用是把一个对象插入到一个进程的句柄表中，也通过ObpLookupObjectName函数来验证待插入的对象是否在全局名字空间中

​    对象管理器中的对象是执行体对象，他们位于系统地址空间中，因而所有的进程都可以访问这些对象。但是用户模式的代码只能通过系统调用和句柄表来引用执行体对象。内核中将一个句柄转化为相应的对象，可以通过ObReferenceObjectByHandle函数来完成。该函数负责从当前进程环境或内核环境的句柄表中获得指定的对象引用。

​    对象是通过引用计数来管理其生命周期的，一旦引用计数为0，则对象生命周期结束，它所占用的内存也可以被回收。