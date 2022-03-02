---
title: Angr初探
date: 2021-06-26
tags: 符号执行
---

## 一、介绍

    首先我将简要介绍一下Angr，因为我认为知道我们的工具如何工作是很重要的一件事情。

## 二、符号执行 - 简要介绍

Angr是一个python模块的，我将使用它作为二进制分析的框架。它是采用动态和静态结合的方式来进行符号分析的工作。这种工作方式被叫做“导向性随机测试”，虽然如此，但是大家基本叫它符号执行/分析引擎。

### 什么是符号执行？

    符号执行就是通过用“符号”值替换程序的输入值来模拟程序的执行。随着执行模拟的进行，每当处理输入时，执行程序的约束条件都会被添加到“符号”值中。 当遇到分支条件时，模拟分为两条路径：一条路径分支条件评估为真，另一条路径评估为假。

通俗的说，就是用符号去替换输入的值。用符号值执行程序会建立起约束的边界。
看下面的一个例子：

```
// Assume a & b are controlled by the user
if (a > b)
  a = a - b;
else b = b - a;
```

也就是说，左分支的约束是 a>b，而右分支的约束是 a<=b。

真实世界的程序肯定不会如此简单，代码分支深处的约束会变得非常大、非常快。为了解决这些限制，Angr使用了微软的定理证明器Z3。Z3检查约束是否可满足 (SAT)。假设某个分支有可满足的约束，我们可以要求Angr给出一个满足约束的输入的例子。

## 三、Angr - 基础使用

下面是一个Angr基础使用的用法示例。在下面的例子中，我们将会添加约束条件，并让Angr去执行它。
考虑下面的代码片段：

```
#include <stdio.h>
#include <stdlib.h>

void main(int argc, char *argv[]){
    int a=atoi(argv[1]);
    int b=atoi(argv[2]);
    if (10 > a && a > 5 && 10 > b && b > 1 && 2*b - a == 10)
    {
        printf("[+] Math is hard... but not 4 u! \n");
    }
}
```

我们将会使用Angr手工的加上约束条件，然后使用内置的求解器（solver）进行求解。这与我们通常使用Angr的方式不同，它只是在我们深入研究复杂案例之前展示一下的例子。

带上注释一步一步的用iPython命令，

```python
# Importing angr
In [1]: import angr 

# A wrapper for Z3. Claripy is used for constraint-solving.
In [2]: import claripy 

# Loading the binary to angr. 
In [3]: p = angr.Project('./a.out') 
WARNING | 2021-05-24 17:54:05,450 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.

# Constructs a state ready to execute at the binary's entry point.
In [4]: state = p.factory.entry_state() 

# Create a bitvector symbol named "a" of length 32 bits
In [5]: a = state.solver.BVS("a", 32) 

# Create a bitvector symbol named "b" of length 32 bits
In [6]: b = state.solver.BVS("b", 32) 

''' Adding constraints manually '''
In [7]: state.solver.add(10>a) 
Out[7]: [<Bool a_39_32 < 0xa>]

In [8]: state.solver.add(a>5)
Out[8]: [<Bool a_39_32 > 0x5>]

In [9]: state.solver.add(b>1)
Out[9]: [<Bool b_40_32 > 0x1>]

In [10]: state.solver.add(b<10)
Out[10]: [<Bool b_40_32 < 0xa>]

In [11]: state.solver.add(2*b - a == 10)
Out[11]: [<Bool 0x2 * b_40_32 - a_39_32 == 0xa>]

# Evaluates the value of "a" by taking the current constraints into consideration.
In [12]: state.solver.eval(a)
Out[12]: 6

# Evaluates the value of "b" by taking the current constraints into consideration.
In [13]: state.solver.eval(b)
Out[13]: 8
```

现在我们有了这些基础之后，让我们转到主要的事情上：

## 四、逆向混淆的二进制文件

我们使用的二进制文件是“[DarkCTF2020](https://ctftime.org/event/1118)”的“[Jack](https://napongizero.github.io/blog/assets/Defeating-Code-Obfuscation-with-Angr/jack)”

### 文件分析

首先收集一些二进制文件的基础信息：

```
$ file ./jack
./jack: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f530c71efca944a196fe383afcd8df60591edf78, for GNU/Linux 3.2.0, not stripped
```

执行下文件，并且使用ltrace去trace写库函数。

```
$ ltrace ./jack
puts("Enter your key: "Enter your key: 
)                         = 17
fgets(adf
"adf\n", 17, 0x7f8f337f0a00)               = 0x7ffd58fe1040
strlen("adf\n")                                  = 4
puts("Try Harder"Try Harder
)                               = 11
puts("bye"bye
)                                      = 4
+++ exited (status 1) +++

```

这为我们提供了一些关于我们面对的问题的有用的信息。
看来问题是找到程序的key（可能不止一个）。
接下来，我决定在 Ghidra 中加载二进制文件，以便更好地了解发生了什么。

反编译主程序：

```
bool main(void)

{
  uint uVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  char local_28;
  char local_27;
  char local_26;
  char local_25;
  char local_24;
  char local_23;
  char local_22;
  char local_21;
  char local_20;
  char local_1f;
  char local_1e;
  char local_1d;
  char local_1c;
  char local_1b;
  char local_1a;
  char local_19;
  undefined local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Enter your key: ");
  fgets(&local_28,0x11,stdin);
  local_18 = 0;
  sVar2 = strlen(&local_28);
  if (sVar2 != 0x10) {
    puts("Try Harder");
  }
  else {
    local_38 = local_25 * 0x1000000 + (int)local_28 + local_27 * 0x100 + local_26 * 0x10000;
    local_38 = local_38 ^ ((int)local_38 >> 3 & 0x20000000U) + local_38 * 0x20;
    local_38 = local_38 ^ local_38 << 7;
    local_38 = (local_38 >> 1 & 0xff) + local_38;
    local_38 = ((int)local_38 >> 3 & 0x20000000U) + local_38 * 0x20 ^ local_38;
    local_38 = local_38 ^ local_38 << 7;
    local_38 = local_38 + (local_38 >> 1 & 0xff);
    uVar1 = local_21 * 0x1000000 + (int)local_24 + local_23 * 0x100 + local_22 * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_34 = uVar1 + (uVar1 >> 1 & 0xff);
    uVar1 = local_1d * 0x1000000 + (int)local_20 + local_1f * 0x100 + local_1e * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_30 = uVar1 + (uVar1 >> 1 & 0xff);
    uVar1 = local_19 * 0x1000000 + (int)local_1c + local_1b * 0x100 + local_1a * 0x10000;
    uVar1 = uVar1 ^ ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20;
    uVar1 = uVar1 ^ uVar1 << 7;
    uVar1 = (uVar1 >> 1 & 0xff) + uVar1;
    uVar1 = ((int)uVar1 >> 3 & 0x20000000U) + uVar1 * 0x20 ^ uVar1;
    uVar1 = uVar1 ^ uVar1 << 7;
    local_2c = uVar1 + (uVar1 >> 1 & 0xff);
    check_flag(&local_38);
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return sVar2 != 0x10;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

看到这我们可以确定输入有16个字符长。

```
if (sVar2 != 0x10) {
    puts("Try Harder");
  }
  else {
```

然后经过一连串的异或移位，加法，乘法之后，调用了check_flag

```
/* check_flag(unsigned int*) */

void check_flag(uint *param_1)

{
  if ((((*param_1 == 0xcb9f59b7) && (param_1[1] == 0x5b90f617)) && (param_1[2] == 0x20e59633)) &&
     (param_1[3] == 0x102fd1da)) {
    puts("Good Work!");
    return;
  }
  puts("Try Harder");
  return;
}
```

假设我们的目标是来到“Good Work!”这一行。我们需要找到程序的正确的输入，（也许这里有多个答案，因为这个移位操作）。

我们有以下的几个选择：
>\>暴力破解，16个字符，可能是字母符号数字...暴力太难了
>\>逆向-动态/静态分析，尽管逆向不是很有趣，我们也可以在运行时改变一下param_1的值通过hook的方式...
>\>打补丁，通过打补丁的方式让他到puts这里。但让我们假设我们不想做任何的改变。
>\>符号执行（Angr），我们今天的明显选择。另外，它为我们提供了一个实际有效的程序输入。

### Angr
首先我们加载需要的库：

```
import angr
import claripy
```

接下来，我们将设置程序的基地址并通过 Angr 加载二进制文件。
我们会设置程序的基地址，并且设置"auto_load_libs"为false。
*注意：设置"auto_load_libs"为false，将禁止CLE（Angr的二进制文件加载器）自动处理动态库依赖。我建议使用它，防止当某个动态库无法找到时，抛出异常。*

```
# Ghidra loaded the binary to 0x00100000 (default Image Base)
base_addr = 0x00100000 

proj = angr.Project('./jack', main_opts={'base_addr': base_addr}, load_options={"auto_load_libs": False})
```

填上我们收集的二进制文件信息：
我们知道我们的输入需要16个字符的长度，因此，我们需要为我们的16个字符创建一个符号位向量。在把它们链接到一起之前，我为每个输入字节创建一个位向量。

*注意：位向量本质只是一串位序列，一个符号位向量只是一个符号变量，它在某种意义上不是保存具体的数值，而是保存一个符号。然后，使用该变量执行算术运算将产生一个运算树（根据编译器理论称为抽象语法树或 AST）。如示例中所示，AST 可以转换为约束。*

```
input_length = 16

# claripy.BVS('x', 8) => Create an eight-bit symbolic bitvector "x".
# Creating a symbolic bitvector for each character:
input_chars = [claripy.BVS("char_%d" % i, 8) for i in range(input_length)]
input = claripy.Concat(*input_chars)
```

接下来，在将程序的输入设置为stdin的同时获取程序的入口状态。

```
entry_state = proj.factory.entry_state(args=["./jack"], stdin=input)
```

添加约束条件，以便每个字符都必须在可打印的 ascii 范围内。 这只是我的一个假设，我们不知道它是真是假。

```
for byte in input_chars:
    entry_state.solver.add(byte >= 0x20, byte <= 0x7e)

```

现在我们已经完成了设置，我们可以用符号模拟二进制的执行了。我们还需要关键的一个东西SimulationManager。有了它我们就可以控制多种状态，step() run()就像调试器一样。

```
# Establish the simulation with the entry state
simulation = proj.factory.simulation_manager(entry_state)
```

现在我们可以使用符号执行程序了，我们应该设置一些目标。我们可以设置Angr应该运行到哪，哪一个分支不用关心

```
success_addr = 0x00101489 # Address of "puts("Good Work!");"
failure_addr = 0x00101468 # Address of "puts("Try Harder");"

# Finding a state that reaches `success_addr`, while discarding all states that go through `failure_addr`
simulation.explore(find = success_addr, avoid = failure_addr)
```

检查我们是否执行到success_addr就很简单了：

```
# If at least one state was found
if len(simulation.found) > 0:
    # Take the first one and print what it evaluates to
    solution = simulation.found[0]
    print(solution.solver.eval(input, cast_to=bytes))
else:
    print("[-] no solution found :(")

```

在原来的程序上执行脚本的结果，

```
b'n0_5ymb0l1c,3x30'

❯ ./jack
Enter your key: 
n0_5ymb0l1c,3x30
Good Work!
bye
```

## 六、结论

Angr在有些情况下，比如在上面的例子中，的确非常有用，你可以使用它作为一个单独的工具或者一些逆向工具的开源插件，例如：IDA，Ghidra，Binary Ninja或者更多。
