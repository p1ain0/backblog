---
title: ARM-Instractions
date: 2021-08-11
tags: ARM
---

## DATA Types

与高级语言相似，ARM支持操作不同类型的数据类型。我们可以load（or stroe）的数据类型有signed and unsigned words、halfwords、or bytes. 这些数据类型的extensions分别是：halfwords是-h or -sh，bytes是-b or -sb，word没有extension. signed and unsinged 数据的区别：
    1.signed data type 能储存正数和负数，因此范围较小
    2.unsigned data type 可以保存大的正值（包括“零”），但不能保存负值，因此范围更广。

以下是一些load和store指令的操作指令的一些例子：

```c
ldr = Load Word
ldrh = Load unsigned Half Word
ldrsh = Load signed Half Word
ldrb = Load unsigned Byte
ldrsb = Load signed Bytes

str = Store Word
strh = Store unsigned Half Word
strsh = Store signed Half Word
strb = Store unsigned Byte
strsb = Store signed Byte
```

查看内存中的字节有两种基本方式：Little-Endian (LE) 或 Big-Endian (BE)。 区别在于对象的每个字节存储在内存中的字节顺序。 在像 Intel x86 这样的小端机器上，最低有效字节存储在最低地址（最接近零的地址）。 在 big-endian 机器上，最高有效字节存储在最低地址。 ARM 体系结构在第 3 版之前是小端的，从那时起它是双端的，这意味着它具有允许可切换的端的设置。 例如，在 ARMv6 上，指令是固定的 little-endian，数据访问可以是 little-endian 或 big-endian，由程序状态寄存器 (CPSR) 的第 9 位（E 位）控制。

寄存器的数量是依赖于ARM的版本的，通过查询ARM Reference Manual，除了基于 ARMv6-M 和 ARMv7-M 的处理器外，都有 30 个通用 32 位寄存器，前 16 个寄存器(r1-r15)可在用户级模式下访问，其他寄存器可在特权软件执行中使用（ARMv6-M 和 ARMv7-M 除外）。

| # | Alias | Purpose |
|---|-------|-------|
| R0 | \- |General purppose|
| R1 | \- |General purppose|
| R2 | \- |General purppose|
| R3 | \- |General purppose|
| R4 | \- |General purppose|
| R5 | \- |General purppose|
| R6 | \- |General purppose|
| R7 | \- |General purppose|
| R8 | \- |General purppose|
| R9 | \- |General purppose|
| R10 | \- |General purppose|
| R11 | FP |Frame Pointer|
| R12 | IP |Instra Procedural Call|
| R13 | SP |Stack Pointer|
| R14 | LR |Link Register|
| R15 | PC |Program Counter|
| CPSR | \- |Current Program Status Register|

下表只是快速了解 ARM 寄存器如何与 Intel 处理器中的寄存器相关联。

|ARM|Description|x86
|---|---|---|
R0|General Purpose|EAX
R1-R5|General Purpose|EBX, ECX, EDX, ESI, EDI
R6-R10|General Purpose|–
R11 (FP)|Frame Pointer|EBP
R12|Intra Procedural Call|–
R13 (SP)|Stack Pointer|ESP
R14 (LR)|Link Register|–
R15 (PC)|<- Program Counter / Instruction Pointer ->|EIP
CPSR|Current Program State Register/Flags|EFLAGS

R0-R12：在普通的操作中可以被用作储存临时数据、指针等等。例如，R0 可在算术运算期间称为累加器或用于存储先前调用函数的结果。 R7 在处理系统调用时变得有用，因为它存储系统调用编号，而 R11 帮助我们跟踪用作帧指针的堆栈边界。 此外，ARM 上的函数调用约定指定函数的前四个参数存储在寄存器 r0-r3 中。

R13：SP(Stack Pointer). 这个栈指针指向栈顶，栈是用于特定于函数的存储的内存区域，在函数返回时被回收。 因此，栈指针用于在栈上分配空间，方法是从栈指针中减去我们想要分配的值（以字节为单位）。 换句话说，如果我们想分配一个 32 位的值，我们从栈指针中减去 4。

R14:LR(Link Register). 当一个函数调用被执行了，链接寄存器就会更新为下一条指令的内存地址。止痒允许程序在子函数完成后返回到父函数中接着执行。

R15:PC(Program Counter).程序计数器根据所执行指令的大小自动递增。 此大小在 ARM 状态下始终为 4 个字节，在 THUMB 模式下始终为 2 个字节。 当执行分支指令时，PC 持有目的地址。 在执行过程中，PC 在 ARM 状态下存储当前指令加 8（两条 ARM 指令）的地址，在 Thumb(v1) 状态下存储当前指令加 4（两条 Thumb 指令）的地址。 这与 x86 不同，在 x86 中 PC 总是指向要执行的下一条指令。

### 下面在调试器下看一下PC寄存器的行为

源程序如下：

```arm
.section .text
.global _start

_start:
 mov r0, pc
 mov r1, #2
 add r2, r1, r1
 bkpt
```

在GDB中我们设置断点_start然后运行

```s
gef> b _start
Breakpoint 1 at 0x10054
gef> r
```

断点的现场状态如下：

```s
Breakpoint 1, 0x00010054 in _start ()
---------------------------------------------------------------[ registers ]----
$r0   : 0x00000000
$r1   : 0x00000000
$r2   : 0x00000000
$r3   : 0x00000000
$r4   : 0x00000000
$r5   : 0x00000000
$r6   : 0x00000000
$r7   : 0x00000000
$r8   : 0x00000000
$r9   : 0x00000000
$r10  : 0x00000000
$r11  : 0x00000000
$r12  : 0x00000000
$sp   : 0xbefff3b0 -> 0x00000001
$lr   : 0x00000000
$pc   : 0x00010054 -> <_start+0> mov r0,  pc
$cpsr : [thumb fast interrupt overflow carry zero negative]
-------------------------------------------------------------------[ stack ]----
0xbefff3b0|+0x00: 0x00000001    <-$sp
0xbefff3b4|+0x04: 0xbefff51c -> "/home/pi/asm/test_pc"
0xbefff3b8|+0x08: 0x00000000
0xbefff3bc|+0x0c: 0xbefff531 -> 0x49464e49
0xbefff3c0|+0x10: 0xbefff56b -> "XDG_SESSION_ID=c2"
0xbefff3c4|+0x14: 0xbefff57d -> "SHELL=/bin/bash"
0xbefff3c8|+0x18: 0xbefff58d -> "TERM=xterm"
0xbefff3cc|+0x1c: 0xbefff598 -> 0x49464e49
-------------------------------------------------------------[ code:armv5t ]----
      0x1003c                  andeq  r0,  r1,  r0
      0x10040                  andeq  r0,  r1,  r0
      0x10044                  andeq  r0,  r0,  r4,  rrx
      0x10048                  andeq  r0,  r0,  r4,  rrx
      0x1004c                  andeq  r0,  r0,  r5
      0x10050                  andeq  r0,  r1,  r0
->   0x10054 <_start+0>       mov    r0,  pc
      0x10058 <_start+4>       mov    r1,  #2
      0x1005c <_start+8>       add    r2,  r1,  r1
      0x10060 <_start+12>      bkpt   0x0000
      0x10064                  andeq  r1,  r0,  r1,  asr #6
      0x10068                  cmnvs  r5,  r0,  lsl #2
-----------------------------------------------------------------[ threads ]----
[#0] Id 1, Name: "test_pc", stopped, reason: BREAKPOINT
-------------------------------------------------------------------[ trace ]----
[#0] 0x10054->Name: _start()
-------------------------------------------------------------------------------- 
```

单步运行后：

```s
0x00010058 in _start ()
--------------------------------------------------------------------------------------------------------------------------------------------------------------------[ registers ]----
$r0   : 0x0001005c -> <_start+8> add r2,  r1,  r1
$r1   : 0x00000000
$r2   : 0x00000000
$r3   : 0x00000000
$r4   : 0x00000000
$r5   : 0x00000000
$r6   : 0x00000000
$r7   : 0x00000000
$r8   : 0x00000000
$r9   : 0x00000000
$r10  : 0x00000000
$r11  : 0x00000000
$r12  : 0x00000000
$sp   : 0xbefff3b0 -> 0x00000001
$lr   : 0x00000000
$pc   : 0x00010058 -> <_start+4> mov r1,  #2
$cpsr : [thumb fast interrupt overflow carry zero negative]
------------------------------------------------------------------------------------------------------------------------------------------------------------------------[ stack ]----
0xbefff3b0|+0x00: 0x00000001    <-$sp
0xbefff3b4|+0x04: 0xbefff51c -> "/home/pi/asm/test_pc"
0xbefff3b8|+0x08: 0x00000000
0xbefff3bc|+0x0c: 0xbefff531 -> 0x49464e49
0xbefff3c0|+0x10: 0xbefff56b -> "XDG_SESSION_ID=c2"
0xbefff3c4|+0x14: 0xbefff57d -> "SHELL=/bin/bash"
0xbefff3c8|+0x18: 0xbefff58d -> "TERM=xterm"
0xbefff3cc|+0x1c: 0xbefff598 -> 0x49464e49
------------------------------------------------------------------------------------------------------------------------------------------------------------------[ code:armv5t ]----
      0x10040                  andeq  r0,  r1,  r0
      0x10044                  andeq  r0,  r0,  r4,  rrx
      0x10048                  andeq  r0,  r0,  r4,  rrx
      0x1004c                  andeq  r0,  r0,  r5
      0x10050                  andeq  r0,  r1,  r0
      0x10054 <_start+0>       mov    r0,  pc
->   0x10058 <_start+4>       mov    r1,  #2
      0x1005c <_start+8>       add    r2,  r1,  r1
      0x10060 <_start+12>      bkpt   0x0000
      0x10064                  andeq  r1,  r0,  r1,  asr #6
      0x10068                  cmnvs  r5,  r0,  lsl #2
      0x1006c                  tsteq  r0,  r2,  ror #18
----------------------------------------------------------------------------------------------------------------------------------------------------------------------[ threads ]----
[#0] Id 1, Name: "test_pc", stopped, reason: SINGLE STEP
------------------------------------------------------------------------------------------------------------------------------------------------------------------------[ trace ]----
[#0] 0x10058->Name: _start()
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
```

奇妙的事情发生了，查看R0中的地址。 虽然我们希望 R0 包含先前读取的 PC 值 (0x10054)，但它保存的是我们先前读取的 PC (0x1005c) 前两条指令的值。 从这个例子可以看出，当我们直接读取PC时，它遵循PC指向下一条指令的定义； 但在调试时，PC 指向当前 PC 值（0x10054 + 8 = 0x1005C）之前的两条指令。 这是因为较旧的 ARM 处理器总是在当前执行的指令之前获取两条指令。 ARM 保留此定义的原因是为了确保与早期处理器的兼容性。

### 状态寄存器

寄存器 $CPSR 显示当前程序状态寄存器 (CPSR) 的值，在其下方您可以看到标志拇指、快速中断、溢出、进位、零和负数。 这些标志代表 CPSR 寄存器中的某些位，根据 CPSR 的值设置，激活时变为1。 N、Z、C 和 V 位与 x86 上 EFLAG 寄存器中的 SF、ZF、CF 和 OF 位相同。 这些位用于在程序集级别支持条件和循环中的条件执行

|N|Z|C|V|Q|-| J|-| GE|-| E| A |I|F|T|M
|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|-|
Negative|Zero|Carry|Overflow|underflow| |Jazelle| |Greater than or Equal for SIMD| |Endianness| Abort disable| IRQ disable | FIQ disable | Thumb| Processor mode(Privilege mode)|

Flag|Description
---|---|
N(Negative)|如果指令结果是负数则置1.
Z(Zero)|如果指令结果产生零值则置1.
C(Carry)|如果指令的结果产生一个需要第 33 位才能完全表示的值，则置1.
V(Overflow)|如果该指令的结果产生不能在32位二进制补码表示的值.
E(Endian-bit)|ARM 可以以小端或大端方式运行。 对于小端模式，该位设置为 0，对于大端模式设置为 1.
T(Thumb-bit)|如果是Thumb模式置1，如果是ARM模式置0.
M(Mode-bits)|这些位指定当前特权模式（USR、SVC 等）.
J(Jazelle)|允许某些 ARM 处理器在硬件中执行 Java 字节码的第三种执行状态.

APSR包含下列ALU的状态标志：

N-当操作结果为负数时设置；

Z-当操作结果为0时设置；

C-当操作导致进位时设置；

V-当操作造成溢出时设置。

在下列情况下，进位发生:

1. 如果加法的结果大于或等于 2^32，
2. 如果减法的结果是正数或零，
3. 作为move or logical指令中的内联桶形移位器操作的结果。

如果加法、减法或比较的结果大于或等于 2^31，或小于 –2^31，溢出发生。

## Mode

ARM 处理器有两个主要的状态可以运行（这里不计算 Jazelle），ARM 和 Thumb。 这些状态与特权级别无关。 例如，在 SVC 模式下运行的代码可以是 ARM 或 Thumb。 这两种状态的主要区别在于指令集，其中ARM状态的指令总是32位的，Thumb状态的指令是16位的（但也可以是32位的）。 了解何时以及如何使用 Thumb 对于我们的 ARM 漏洞利用开发目的尤其重要。 在编写 ARM shellcode 时，我们需要去掉 NULL 字节，使用 16 位 Thumb 指令而不是 32 位 ARM 指令减少了拥有它们的机会。

这里有不同的Thumb版本：

1. Thumb-1 (16-bit instructions): 在 ARMv6 and 更早的架构中使用.
2. Thumb-2 (16-bit and 32-bit instructions): 扩展了 Thumb-1 通过加了更多的指令并且允许它们可以是16bits和32bits(ARMv6T2, ARMv7).
3. ThumbEE: 包含了一些改变和添加使其能够动态的添加和生成代码（在执行之前或执行期间在设备上编译的代码）。

ARM和Thumb之间的差别：

1. 条件执行，ARM状态下的所有的指令都支持条件执行，某些 ARM 处理器版本允许使用 IT 指令在 Thumb 中进行条件执行。 条件执行导致更高的代码密度，因为它减少了要执行的指令数量并减少分支预测的指令数量。
2. 32位的ARM和Thumb指令：32位的Thumb指令有.w后缀。
3. 桶形移位器是另一个独特的 ARM 模式功能。 它可用于将多条指令压缩为一条指令。例如，不使用两条指令进行乘法（将寄存器乘以 2 并使用 MOV 将结果存储到另一个寄存器中），您可以通过使用左移 1 -> `Mov R1, R0, LSL #1` 将乘法包含在 MOV 指令中; `R1 = R0 * 2`.

要切换处理器执行的状态，必须满足以下两个条件之一：

1. 我们可以使用分支指令BX (branch and exchange) or BLX (branch, link, and exchange) ，将目标寄存器的最低有效位设置为 1。这可以通过向偏移量加 1 来实现，例如 0x5530 + 1。您可能认为这会导致对齐问题，因为指令是 2 字节或 4 字节对齐的。 这不是问题，因为处理器将忽略最低有效位。
2. 如果当前程序状态寄存器中的 T 位被设置，我们就知道我们处于 Thumb 模式。

### Briefly introduce into ARM Instructions

汇编语言由作为主要构建块的指令组成。 ARM 指令通常后跟一两个操作数，一般使用以下模板：

```s
MNEMONIC{S}{condition} {Rd}, Operand1, Operand2
```

由于 ARM 指令集的灵活性，并非所有指令都使用模板中提供的所有字段。模板中字段的用途描述如下：

```s
MNEMONIC     - Short name (mnemonic) of the instruction
{S}          - An optional suffix. If S is specified, the condition flags are updated on the result of the operation
{condition}  - Condition that is needed to be met in order for the instruction to be executed
{Rd}         - Register (destination) for storing the result of the instruction
Operand1     - First operand. Either a register or an immediate value 
Operand2     - Second (flexible) operand. Can be an immediate value (number) or a register with an optional shift
```

MNEMONIC、S、Rd 和 Operand1 字段是比较直观的，但条件和 Operand2 字段需要更多说明。 条件字段与 CPSR 寄存器的值密切相关，或者准确地说，是寄存器中特定位的值。 Operand2 被称为灵活操作数，因为我们可以以各种形式使用它——作为立即数（具有有限的值集）、寄存器或带有移位的寄存器。 例如，我们可以将这些表达式用作 Operand2：

```arm
#123                    - Immediate value (with limited set of values). 
Rx                      - Register x (like R1, R2, R3 ...)
Rx, ASR n               - Register x with arithmetic shift right by n bits (1 = n = 32)
Rx, LSL n               - Register x with logical shift left by n bits (0 = n = 31)
Rx, LSR n               - Register x with logical shift right by n bits (1 = n = 32)
Rx, ROR n               - Register x with rotate right by n bits (1 = n = 31)
Rx, RRX                 - Register x with rotate right by one bit, with extend
```

不同种类的指令的例子如下所示：

```arm
ADD   R0, R1, R2         - Adds contents of R1 (Operand1) and R2 (Operand2 in a form of register) and stores the result into R0 (Rd)
ADD   R0, R1, #2         - Adds contents of R1 (Operand1) and the value 2 (Operand2 in a form of an immediate value) and stores the result into R0 (Rd)
MOVLE R0, #5             - Moves number 5 (Operand2, because the compiler treats it as MOVLE R0, R0, #5) to R0 (Rd) ONLY if the condition LE (Less Than or Equal) is satisfied
MOV   R0, R1, LSL #1     - Moves the contents of R1 (Operand2 in a form of register with logical shift left) shifted left by one bit to R0 (Rd). So if R1 had value 2, it gets shifted left by one bit and becomes 4. 4 is then moved to R0.
```

总结下：

Instruction|Description|Instruction|Description
--|--|--|--
MOV|Move data|EOR|Bitwise XOR
MVN|Move and negate|LDR|Load
ADD|Addition|STR|Store
SUB|Subtraction|LDM|Load Multiple
MUL|Multiplication|STM|Store Multiple
LSL|Logical Shift Left|PUSH|Push on Stack
LSR|Logical Shift Right|POP|Pop off Stack
ASR|Arithmetic Shift Right|B|Branch
ROR|Rotate Right|BL|Branch with Link
CMP|Compare|BX|Branch and eXchange
AND|Bitwise AND|BLX|Branch with Link and eXchange
ORR|Bitwise OR|SWI/SVC|System Call

## load and store Instruction

ARM使用load-store模式进行内存的访问，这意味着只能使用load/store(LDR and LDR)指令能访问内存。而x86允许直接在内存上操作数据，在arm上数据在操作前必须被move到寄存器中。这意味着在 ARM 上的特定内存地址处递增 32 位值将需要三种类型的指令(load, increment, and store) 来首先将特定地址处的值加载到寄存器中，在寄存器中递增它，然后将它从寄存器存储回内存。为了解释 ARM 上加载和存储操作的基本原理，我们从一个基本示例开始，然后继续介绍三种基本偏移量形式，每种偏移量形式具有三种不同的地址模式。 对于每个示例，我们将使用具有不同 LDR/STR 偏移形式的同一段汇编代码，以保持简单。

立即数作为偏移：
地址模式: 偏移
地址模式: 预先索引
地址模式: 后索引
寄存器作为偏移:
地址模式: 偏移
地址模式: 预先索引
地址模式: 后索引
Scaled register作为偏移
地址模式: 偏移
地址模式: 预先索引
地址模式: 后索引

通常，LDR用于将内存中的某些内容加载到寄存器中，STR用于将存储器中的某些内容存储到内存地址。

```arm
LDR R2, [R0]   @ [R0] - origin address is the value found in R0.
STR R2, [R1]   @ [R1] - destination address is the value found in R1.
```

LDR操作：将R0中找到的地址上的值加载到目标寄存器R2。

STR操作：将R2中找到的值存储到R1中找到的内存地址。

### example 1

```arm
.data          /* the .data section is dynamically created and its addresses cannot be easily predicted */
var1: .word 3  /* variable 1 in memory */
var2: .word 4  /* variable 2 in memory */

.text          /* start of the text (code) section */ 
.global _start

_start:
    ldr r0, adr_var1  @ load the memory address of var1 via label adr_var1 into R0 
    ldr r1, adr_var2  @ load the memory address of var2 via label adr_var2 into R1 
    ldr r2, [r0]      @ load the value (0x03) at memory address found in R0 to register R2  
    str r2, [r1]      @ store the value found in R2 (0x03) to the memory address found in R1 
    bkpt             

adr_var1: .word var1  /* address to var1 stored here */
adr_var2: .word var2  /* address to var2 stored here */
```

在底部，我们有我们的 Literal Pool（同一代码段中的一个内存区域，用于存储其他人可以以与位置无关的方式引用的常量、字符串或偏移量），其中存储了 var1 和 var2 的内存地址（在顶部的数据部分）使用标签 adr_var1 和 adr_var2。第一个 LDR 将 var1 的地址加载到寄存器 R0 中。第二个 LDR 对 var2 执行相同的操作并将其加载到 R1。然后我们将存储在 R0 中找到的内存地址的值加载到 R2，并将 R2 中找到的值存储到 R1 中找到的内存地址。

当我们将某些内容加载到寄存器中时，方括号 ([ ]) 表示：在这些方括号之间的寄存器中找到的值是我们要从中加载某些内容的内存地址。

当我们将内容存储到内存位置时，方括号 ([]) 表示：在这些方括号之间的寄存器中找到的值是我们想要存储内容的内存地址。

调试器中的代码片段：

```arm
->   0x10074 <_start+0>       ldr    r0,  [pc,  #12]    ; 0x10088 <adr_var1>
      0x10078 <_start+4>       ldr    r1,  [pc,  #12]     0x1008c <adr_var2>
      0x1007c <_start+8>       ldr    r2,  [r0]
      0x10080 <_start+12>      str    r2,  [r1]
      0x10084 <_start+16>      bkpt   0x0000
      0x10088 <adr_var1+0>     muleq  r2,  r0,  r0
----------------------------------------------------------------------------------------------------------------------------------------------------------------------[ threads ]----
[#0] Id 1, Name: "test_pc", stopped, reason: BREAKPOINT
------------------------------------------------------------------------------------------------------------------------------------------------------------------------[ trace ]----
[#0] 0x10074->Name: _start()
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
gef> 

```

我们在前两个 LDR 操作中指定的标签更改为 [pc, #12]。这称为 PC 相对寻址。因为我们使用了标签，所以编译器计算了我们在文字池 (PC+12) 中指定的值的位置。您可以使用这种精确方法自己计算位置，也可以像我们之前所做的那样使用标签。唯一的区别是，您需要计算您的值在 Literal Pool 中的确切位置，而不是使用标签。在这种情况下，它距离有效 PC 位置 3 跳（4+4+4=12）。

#### 立即数作为偏移

```arm
STR    Ra, [Rb, imm]
LDR    Ra, [Rc, imm]
```

这里我们使用立即数（整数）作为偏移量。 该值与基址寄存器（下例中的 R1）相加或相减，以在编译时已知的偏移量处访问数据。

```arm
.data
var1: .word 3
var2: .word 4

.text
.global _start

_start:
    ldr r0, adr_var1  @ load the memory address of var1 via label adr_var1 into R0
    ldr r1, adr_var2  @ load the memory address of var2 via label adr_var2 into R1
    ldr r2, [r0]      @ load the value (0x03) at memory address found in R0 to register R2 
    str r2, [r1, #2]  @ address mode: offset. Store the value found in R2 (0x03) to the memory address found in R1 plus 2. Base register (R1) unmodified. 
    str r2, [r1, #4]! @ address mode: pre-indexed. Store the value found in R2 (0x03) to the memory address found in R1 plus 4. Base register (R1) modified: R1 = R1+4 
    ldr r3, [r1], #4  @ address mode: post-indexed. Load the value at memory address found in R1 to register R3. Base register (R1) modified: R1 = R1+4 
    bkpt

adr_var1: .word var1
adr_var2: .word var2
```

将在偏移地址模式下执行 STR 操作的下一条指令。 它会将 R2 (0x00000003) 中的值存储到 R1 (0x0001009c) 中指定的内存地址 + 偏移量 (#2) = 0x1009e。

#### 寄存器作为偏移

```arm
STR    Ra, [Rb, Rc]
LDR    Ra, [Rb, Rc]
```

这种偏移形式使用寄存器作为偏移。 这种偏移形式的一个示例用法是当您的代码想要访问在运行时计算索引的数组时。

```arm
.data
var1: .word 3
var2: .word 4

.text
.global _start

_start:
    ldr r0, adr_var1  @ load the memory address of var1 via label adr_var1 to R0 
    ldr r1, adr_var2  @ load the memory address of var2 via label adr_var2 to R1 
    ldr r2, [r0]      @ load the value (0x03) at memory address found in R0 to R2
    str r2, [r1, r2]  @ address mode: offset. Store the value found in R2 (0x03) to the memory address found in R1 with the offset R2 (0x03). Base register unmodified.   
    str r2, [r1, r2]! @ address mode: pre-indexed. Store value found in R2 (0x03) to the memory address found in R1 with the offset R2 (0x03). Base register modified: R1 = R1+R2. 
    ldr r3, [r1], r2  @ address mode: post-indexed. Load value at memory address found in R1 to register R3. Then modify base register: R1 = R1+R2.
    bx lr

adr_var1: .word var1
adr_var2: .word var2
```

在偏移地址模式下执行第一个STR操作后，R2的值（0x00000003）将存储在内存地址0x0001009c + 0x00000003 = 0x0001009F。

#### Scaled寄存器作偏移

```arm
LDR    Ra, [Rb, Rc, <shifter>]
STR    Ra, [Rb, Rc, <shifter>]
```

第三种偏移形式有一个缩放寄存器作为偏移。 在这种情况下，Rb 是基址寄存器，Rc 是立即偏移量（或包含立即值的寄存器）左/右移位 (\<shifter\>) 以缩放立即数。 这意味着桶形移位器用于缩放偏移。 这种偏移形式的一个示例用法是循环遍历数组。

```arm
.data
var1: .word 3
var2: .word 4

.text
.global _start

_start:
    ldr r0, adr_var1         @ load the memory address of var1 via label adr_var1 to R0
    ldr r1, adr_var2         @ load the memory address of var2 via label adr_var2 to R1
    ldr r2, [r0]             @ load the value (0x03) at memory address found in R0 to R2
    str r2, [r1, r2, LSL#2]  @ address mode: offset. Store the value found in R2 (0x03) to the memory address found in R1 with the offset R2 left-shifted by 2. Base register (R1) unmodified.
    str r2, [r1, r2, LSL#2]! @ address mode: pre-indexed. Store the value found in R2 (0x03) to the memory address found in R1 with the offset R2 left-shifted by 2. Base register modified: R1 = R1 + R2<<2
    ldr r3, [r1], r2, LSL#2  @ address mode: post-indexed. Load value at memory address found in R1 to the register R3. Then modifiy base register: R1 = R1 + R2<<2
    bkpt

adr_var1: .word var1
adr_var2: .word var2
```

第一个 STR 操作使用偏移地址模式，并将在 R2 中找到的值存储在从 [r1, r2, LSL#2] 计算出的内存位置，这意味着它以 R1 中的值为基数（在这种情况下，R1 包含 var2 的内存地址)，然后取 R2 (0x3) 中的值，并将其左移 2。下图是尝试可视化如何使用 [r1, r2, LSL#2] 计算内存位置 .

### 在arm上使用立即数

在 ARM 上的寄存器中加载立即值并不像在 x86 上那样简单。您可以使用哪些直接值是有限制的。可以使用一些技巧来绕过这些限制（提示：LDR）。

我们知道每条 ARM 指令都是 32bit 长的，所有指令都是有条件的。我们可以使用16个条件码，一个条件码占指令的4位。然后我们需要 2 位作为目标寄存器。 2 位用于第一个操作数寄存器，1 位用于设置状态标志，以及用于其他事项（如实际操作码）的各种位。这里的重点是，在为指令类型、寄存器和其他字段分配位后，立即数只剩下 12 位，这将只允许 4096 个不同的值。

这意味着 ARM 指令只能直接在 MOV 中使用有限范围的立即数。如果一个数字不能直接使用，就必须把它分成几部分，由多个较小的数字拼凑起来。

但还有更多。不是将 12 位用于单个整数，而是将这 12 位拆分为一个 8 位数字 (n)，能够加载 0-255 范围内的任何 8 位值，以及一个 4 位旋转字段 (r) 作为一个在 0 到 30 之间以 2 为步长向右循环。这意味着完整的立即数 v 由以下公式给出：v = n ror 2*r。换句话说，唯一有效的立即数是循环字节（可以减少到循环一个偶数的字节的值）。

以下是一些有效和无效的立即数的例子：

```arm
Valid values:
#256        // 1 ror 24 --> 256
#384        // 6 ror 26 --> 384
#484        // 121 ror 30 --> 484
#16384      // 1 ror 18 --> 16384
#2030043136 // 121 ror 8 --> 2030043136
#0x06000000 // 6 ror 8 --> 100663296 (0x06000000 in hex)

Invalid values:
#370        // 185 ror 31 --> 31 is not in range (0 – 30)
#511        // 1 1111 1111 --> bit-pattern can’t fit into one byte
#0x06010000 // 1 1000 0001.. --> bit-pattern can’t fit into one byte
```

这导致无法一次性加载完整的 32 位地址。 我们可以使用以下两个选项之一绕过此限制：

1. 用较小的部分构造较大的值：不使用`Mov r0 ,#511`,分割511到两部分:`MOV r0, #256, and ADD r0, #255`
2. 使用加载结构`ldr r1,=value`，如果不可能，汇编器会很乐意将其转换为 MOV 或与 PC 相关的加载。比如：`LDR r1, =511`

如果你试图加载一个无效的立即数，汇编器会产生一个错误，"Error: invalid constant.",
如果您需要弄清楚某个数字是否可以用作有效的立即数，则无需自己计算。 您可以使用我的名为 [rotator.py](https://raw.githubusercontent.com/azeria-labs/rotator/master/rotator.py) 的小 Python 脚本，它将您的号码作为输入并告诉您它是否可以用作有效的立即数。

rotator.py

```python
from __future__ import print_function   # PEP 3105
import sys

# Rotate right: 0b1001 --> 0b1100
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

max_bits = 32

input = int(raw_input("Enter the value you want to check: "))

print()
for n in xrange(1, 256):

    for i in xrange(0, 31, 2):

        rotated = ror(n, i, max_bits)

        if(rotated == input):
            print("The number %i can be used as a valid immediate number." % input)
            print("%i ror %x --> %s" % (n, int(str(i), 16), rotated))
            print()
            sys.exit()

else:
    print("Sorry, %i cannot be used as an immediate number and has to be split." % input)
```

## load/store 多个值

有时一次加载（或存储）多个值更有效。为此，我们使用LDM（负载倍数）和STM（存储倍数）。这些指令的变体基本上只因访问初始地址的方式而异。这是我们本节将使用的代码。我们将一步一步地完成每项指令。

```arm
.data

array_buff:
 .word 0x00000000             /* array_buff[0] */
 .word 0x00000000             /* array_buff[1] */
 .word 0x00000000             /* array_buff[2]. This element has a relative address of array_buff+8 */
 .word 0x00000000             /* array_buff[3] */
 .word 0x00000000             /* array_buff[4] */

.text
.global _start

_start:
 adr r0, words+12             /* address of words[3] -> r0 */
 ldr r1, array_buff_bridge    /* address of array_buff[0] -> r1 */
 ldr r2, array_buff_bridge+4  /* address of array_buff[2] -> r2 */
 ldm r0, {r4,r5}              /* words[3] -> r4 = 0x03; words[4] -> r5 = 0x04 */
 stm r1, {r4,r5}              /* r4 -> array_buff[0] = 0x03; r5 -> array_buff[1] = 0x04 */
 ldmia r0, {r4-r6}            /* words[3] -> r4 = 0x03, words[4] -> r5 = 0x04; words[5] -> r6 = 0x05; */
 stmia r1, {r4-r6}            /* r4 -> array_buff[0] = 0x03; r5 -> array_buff[1] = 0x04; r6 -> array_buff[2] = 0x05 */
 ldmib r0, {r4-r6}            /* words[4] -> r4 = 0x04; words[5] -> r5 = 0x05; words[6] -> r6 = 0x06 */
 stmib r1, {r4-r6}            /* r4 -> array_buff[1] = 0x04; r5 -> array_buff[2] = 0x05; r6 -> array_buff[3] = 0x06 */
 ldmda r0, {r4-r6}            /* words[3] -> r6 = 0x03; words[2] -> r5 = 0x02; words[1] -> r4 = 0x01 */
 ldmdb r0, {r4-r6}            /* words[2] -> r6 = 0x02; words[1] -> r5 = 0x01; words[0] -> r4 = 0x00 */
 stmda r2, {r4-r6}            /* r6 -> array_buff[2] = 0x02; r5 -> array_buff[1] = 0x01; r4 -> array_buff[0] = 0x00 */
 stmdb r2, {r4-r5}            /* r5 -> array_buff[1] = 0x01; r4 -> array_buff[0] = 0x00; */
 bx lr

words:
 .word 0x00000000             /* words[0] */
 .word 0x00000001             /* words[1] */
 .word 0x00000002             /* words[2] */
 .word 0x00000003             /* words[3] */
 .word 0x00000004             /* words[4] */
 .word 0x00000005             /* words[5] */
 .word 0x00000006             /* words[6] */

array_buff_bridge:
 .word array_buff             /* address of array_buff, or in other words - array_buff[0] */
 .word array_buff+8           /* address of array_buff[2] */
```

在开始之前，请记住，.word 指的是 32 位 = 4 BYTES 的数据（内存）块。 这对于理解偏移很重要。 因此该程序由 .data 部分组成，我们在其中分配了一个具有 5 个元素的空数组 (array_buff)。 我们将使用它作为存储数据的可写内存位置。 .text 部分包含我们的代码以及内存操作指令和一个包含两个标签的只读数据池：一个用于具有 7 个元素的数组，另一个用于“桥接” .text 和 .data 部分，以便我们可以访问驻留的 array_buff 在 .data 部分。

```arm
adr r0, words+12             /* address of words[3] -> r0 */
```

我们使用 ADR 指令将第 4 个元素（words[3]）的地址放入 R0。 我们指向 words 数组的中间，因为我们将从那里向前和向后操作。

我们用 array_buff 数组的第一个 (array_buff[0]) 和第三个 (array_buff[2]) 元素的地址准备 R1 和 R2。 一旦获得地址，我们就可以开始对其进行操作。

下一条指令使用 LDM 从 R0 指向的内存中加载两个字值。 因此，因为我们之前让 R0 指向 words[3] 元素，所以 words[3] 值转到 R4，words[4] 值转到 R5。

下一条指令让我们执行 STM 指令将多个值存储到内存中。 我们代码中的 STM 指令从寄存器 R4 和 R5 获取值（0x3 和 0x4），并将这些值存储到 R1 指定的内存位置。

变体的类型由指令的后缀定义。 示例中使用的后缀是：-IA（之后增加）、-IB（之前增加）、-DA（之后减少）、-DB（之前减少）。 这些变体的不同之处在于它们如何访问由第一个操作数（存储源地址或目标地址的寄存器）指定的内存。 实际上，LDM 与 LDMIA 相同，这意味着每次加载后都会增加下一个要加载的元素的地址。 通过这种方式，我们从第一个操作数（存储源地址的寄存器）指定的内存地址中获得顺序（前向）数据加载。

```arm
ldmia r0, {r4-r6} /* words[3] -> r4 = 0x03, words[4] -> r5 = 0x04; words[5] -> r6 = 0x05; */ 
stmia r1, {r4-r6} /* r4 -> array_buff[0] = 0x03; r5 -> array_buff[1] = 0x04; r6 -> array_buff[2] = 0x05 */
```

执行上述两条指令后，寄存器 R4-R6 和内存地址 0x000100D0、0x000100D4 和 0x000100D8 包含值 0x3、0x4 和 0x5。

LDMIB 指令首先将源地址增加 4 个字节（一个字值），然后执行第一次加载。 通过这种方式，我们仍然可以顺序（向前）加载数据，但第一个元素与源地址有 4 个字节的偏移量。 这就是为什么在我们的示例中，通过 LDMIB 指令从内存加载到 R4 的第一个元素是 0x00000004（word[4]）而不是 R0 指向的 0x00000003（word[3]）。

```arm
ldmib r0, {r4-r6}            /* words[4] -> r4 = 0x04; words[5] -> r5 = 0x05; words[6] -> r6 = 0x06 */
stmib r1, {r4-r6}            /* r4 -> array_buff[1] = 0x04; r5 -> array_buff[2] = 0x05; r6 -> array_buff[3] = 0x06 */
```

执行上述两条指令后，寄存器 R4-R6 和内存地址 0x100D4、0x100D8 和 0x100DC 包含值 0x4、0x5 和 0x6。

当我们使用 LDMDA 指令时，一切都开始向后运行。 R0 指向word[3]。 当加载开始时，我们向后移动并将word[3]、word[2]和word[1]加载到R6、R5、R4中。 是的，寄存器也是反向加载的。 所以在指令完成后 R6 = 0x00000003，R5 = 0x00000002，R4 = 0x00000001。

```arm
ldmda r0, {r4-r6} /* words[3] -> r6 = 0x03; words[2] -> r5 = 0x02; words[1] -> r4 = 0x01 */
```

加载多个，递减后：

```arm
ldmdb r0, {r4-r6} /* words[2] -> r6 = 0x02; words[1] -> r5 = 0x01; words[0] -> r4 = 0x00 */
```

store多个，递减后：

```arm
stmda r2, {r4-r6} /* r6 -> array_buff[2] = 0x02; r5 -> array_buff[1] = 0x01; r4 -> array_buff[0] = 0x00 */
```

### push and pop

PUSH：

1. SP -= 4
2. 信息store到新地址

POP：

1. SP地址处的value被load到指示的register中
2. SP += 4

## 条件执行

Condition Code|Meaning (for cmp or subs)|Status of Flags
---|---|---
EQ|Equal|Z==1
NE|Not Equal|Z==0
GT|Signed Greater Than|(Z==0) && (N==V)
LT|Signed Less Than|N!=V
GE|Signed Greater Than or Equal|N==V
LE|Signed Less Than or Equal|(Z==1) \|\| (N!=V)
CS or HS|Unsigned Higher or Same (or Carry Set)|C==1
CC or LO|Unsigned Lower (or Carry Clear)|C==0
MI|Negative (or Minus)|N==1
PL|Positive (or Plus)|N==0
AL| Always executed| –
NV| Never executed| –
VS| Signed Overflow| V==1
VC| No signed Overflow| V==0
HI| Unsigned Higher|(C==1) && (Z==0)
LS| Unsigned Lower or same| (C==0) \|\| (Z==0)

```arm
.global main

main:
        mov     r0, #2     /* setting up initial variable */
        cmp     r0, #3     /* comparing r0 to number 3. Negative bit get's set to 1 */
        addlt   r0, r0, #1 /* increasing r0 IF it was determined that it is smaller (lower than) number 3 */
        cmp     r0, #3     /* comparing r0 to number 3 again. Zero bit gets set to 1. Negative bit is set to 0 */
        addlt   r0, r0, #1 /* increasing r0 IF it was determined that it is smaller (lower than) number 3 */
        bx      lr
```

上面代码中的第一条 CMP 指令触发负位被置位 (2 – 3 = -1) 表示 r0 中的值低于数字 3。随后执行 ADDLT 指令，因为当 V 时 LT 条件已满！ = N（CPSR 中溢出位和负位的值不同）。 在我们执行第二个 CMP 之前，我们的 r0 = 3。这就是为什么第二个 CMP 清除负位（因为 3 – 3 = 0，不需要设置负标志）并设置零标志（Z = 1）。 现在我们有 V = 0 和 N = 0 这导致 LT 条件失败。 因此，不会执行第二个 ADDLT，并且 r0 保持不变。 程序退出，结果为 3。

### Thumb条件执行

在允许条件执行的 Thumb 版本 (Thumb-2)中。 某些 ARM 处理器版本支持“IT”指令，该指令允许在 Thumb 状态下有条件地执行最多 4 条指令。

语法：IT{x{y{z}}} cond

1. cond 指定 IT 块中第一条指令的条件
2. x 指定 IT 块中第二条指令的条件开关
3. y 指定 IT 块中第三条指令的条件开关
4. z 指定 IT 块中第四条指令的条件开关

IT 指令的结构是“IF-Then-(Else)”，语法是两个字母 T 和 E 的结构：

1. IT 指的是 If-Then（下一条指令是有条件的）
2. ITT 指的是 If-Then-Then（接下来的 2 条指令是有条件的）
3. ITE 指的是 If-Then-Else（接下来的 2 条指令是有条件的）
4. ITTE 指的是 If-Then-Then-Else（接下来的 3 条指令是有条件的）
5. ITTEE 指的是 If-Then-Then-Else-Else（接下来的 4 条指令是有条件的）

IT 块内的每条指令都必须指定一个条件后缀，该后缀相同或逻辑相反。 这意味着，如果您使用 ITE，则第一条和第二条指令 (If-Then) 必须具有相同的条件后缀，而第三条 (Else) 必须具有前两条的逻辑逆。

```arm
ITTE   NE           ; Next 3 instructions are conditional
ANDNE  R0, R0, R1   ; ANDNE does not update condition flags
ADDSNE R2, R2, #1   ; ADDSNE updates condition flags
MOVEQ  R2, R3       ; Conditional move

ITE    GT           ; Next 2 instructions are conditional
ADDGT  R1, R0, #55  ; Conditional addition in case the GT is true
ADDLE  R1, R0, #48  ; Conditional addition in case the GT is not true

ITTEE  EQ           ; Next 4 instructions are conditional
MOVEQ  R0, R1       ; Conditional MOV
ADDEQ  R2, R2, #10  ; Conditional ADD
ANDNE  R3, R3, #1   ; Conditional AND
BNE.W  dloop        ; Branch instruction can only be used in the last instruction of an IT block
```

以下是条件代码及其对立的条件：

Code|Meaning|Code|Meaning
--|--|--|--
EQ|Equal|NE| Not Equal
HS(or CS)|Unsigned higher or same(or carry set)|LO(or CC | Unsigned lower(or carry clear)
MI|Negative|PL| Positive or Zero
VS|Signed Overflow|VC| No Signed Overflow
HI|Unsigned Higher|LS| Unsigned Lower or Same
GE|Signed Greater Than or Equal|LT| Signed Less Than
GT| Signed Greater Than|LE| Signed Less Than or Equal
AL (or omitted)| Always Executed | There is no opposite to AL| --

```arm
.syntax unified    @ this is important!
.text
.global _start

_start:
    .code 32
    add r3, pc, #1   @ increase value of PC by 1 and add it to R3
    bx r3            @ branch + exchange to the address in R3 -> switch to Thumb state because LSB = 1

    .code 16         @ Thumb state
    cmp r0, #10      
    ite eq           @ if R0 is equal 10...
    addeq r1, #2     @ ... then R1 = R1 + 2
    addne r1, #3     @ ... else R1 = R1 + 3
    bkpt
```

.code 32

此示例代码以ARM状态开始。第一条指令将 PC 加 1 指定的地址添加到 R3，然后分支到 R3 中的地址。这将导致切换到拇指状态，因为LSB（最不重要的位）是1，因此不是4字节对齐的。为此使用bx（分支+交换）很重要。在分支之后设置T（拇指）标志，我们处于拇指状态。

.code 16

在拇指状态下，我们首先将R0与#10进行比较，这将设置负标志（0–10 = – 10）。然后我们使用If-Then-Else块。此块将跳过ADDEQ指令，因为没有设置Z（零）标志，并将执行ADDNE指令，因为结果为NE（不等于）为10。

### 分支

#### B / BX / BLX

存在三种类型的分支指令：

Branch (B)

    简单跳转到函数

Branch link (BL)

    在 LR 中保存 (PC+4) 并跳转到函数

Branch exchange (BX) and Branch link exchange (BLX)

    与 B/BL + 交换指令集相同 (ARM <-> Thumb)
    需要一个寄存器作为第一个操作数：BX/BLX reg

### 栈

Stack Type|Store|Load
--|--|--
Full descending|STMFD (STMDB, Decrement Before)|LDMFD (LDM, Increment after)
Full ascending|STMFA (STMIB, Increment Before)|LDMFA (LDMDA, Decrement After)
Empty descending|STMED (STMDA, Decrement After)|LDMED (LDMIB, Increment Before)
Empty ascending|STMEA (STM, Increment after)|LDMEA (LDMDB, Decrement Before)

◎ Full descending 满递减堆栈
堆栈首部是高地址，堆栈向低地址增长。栈指针总是指向堆栈最后一个元素(最后一个元素是最后压入的数据)。
ARM-Thumb过程调用标准和ARM、Thumb C/C++ 编译器总是使用Full descending 类型堆栈。

◎ Full ascending 满递增堆栈
堆栈首部是低地址，堆栈向高地址增长。栈指针总是指向堆栈最后一个元素(最后一个元素是最后压入的数据)。

◎ Empty descending 空递减堆栈
堆栈首部是低地址，堆栈向高地址增长。栈指针总是指向下一个将要放入数据的空位置。

◎ Empty ascending 空递增堆栈
堆栈首部是高地址，堆栈向低地址增长。栈指针总是指向下一个将要放入数据的空位置。