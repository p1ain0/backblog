---
title: afl初探
date: 2021-07-13
tags: fuzzing
---

## 模糊测试六步骤

1.识别目标系统

2.确定输入

3.生成模糊数据

4.使用模糊数据进行测试

5.监控系统的行为

6.记录缺陷

## afl-fuzz浅谈

最近在研究afl-fuzz，发现一些有意思的东西，记录一下。

先说这个afl-fuzz的打桩机制，越想越觉得作者这人脑回路新奇。先说说使用这个方法的初衷。

为了提升性能，afl-fuzz使用了一个"fork server"，fuzz的进程只进行一次execve(), 连接(linking), 库初始化(libc initialization)。fuzz进程通过copy-on-write的方式从已停止的fuzz进程中clone下来。

为了实现copy-on-write功能，作者在编译的时候把初始化操作插入到程序的最开始，把编译后的程序拖到IDA会发现文件格式的DT_INIT_ARRAY里被添加了几个名字带有afl的函数，这几个函数会在程序加载完后先执行，（先于main函数），程序会在这里进行fork()子进程的操作。等待afl-fuzz的命令，接受子进程的状态，并发送给afl-fuzz。

### 源码分析

#### afl-gcc

1.找afl-as的路径，

2.设置编译参数，

3.执行gcc/g++/clang执行真正的编译过程...

```c
......
  //找afl-as的路径
  find_as(argv[0]);

  edit_params(argc, argv);
  
  //打印gcc的命令行参数
  for(int i = 0; i < argc + 128; i++)
  {
    if(cc_params[i])
      printf("%s\n",cc_params[i]);
  }

  execvp(cc_params[0], (char**)cc_params);
......
```

如下是参数的输出情况：

```shell
gcc
/root/AFLcpp/test-instr.c
-o
test-instr
-B
/root/AFLcpp
-g
-O3
-funroll-loops
-D__AFL_COMPILER=1
-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1
```

#### afl-as

这里值得一提的函数就是`add_instrumentation`,也是afl-as的最关键的操作，用来插桩，在处理到某个分支，需要插入桩代码时，afl-as会生成一个随机数，作为运行时保存在ecx中的值。而这个随机数，便是用于标识这个代码块的key。

#### afl-cmin

afl-cmin -i tests/ -o output_dir -- ./proc -e -r @@

trace_bits

#### afl-fuzz.c

参数说明

-i in_dir 输入目录，-o out_dir 输出目录，-M sync_id force_deterministic， -S sync_id，-f out_file target file，-x extras_dir，-t timeout，-m mem_limit，-b cpu_to_bind_given (bind cpu core)，-d skip_deterministic = 1 use_splicing = 1（skip deterministic）-B in_bitmap read_bitmap()，-c crash_mode = FAULT_CRASH，-n dump mode，-T use_banner，-Q qemu_mode，

setup_shm()  
1.初始化virgin_bits, virgin_tmout, virgin_crash三个全局变量。
2.申请并初始化共享变量内存区域。并将该共享变量的值写入环境变量。

init_count_class16()  
初始化count_class_lookup16数组,

setup_dirs_fds()
初始化输出目录

read_testcases()
把输入目录的文件添加到队列中

load_auto()
加载自动生成的附加功能。

pivot_inputs()
在输出目录中为输入测试用例创建硬链接,名字会标记好id和name。

if (extras_dir) load_extras(extras_dir);  由-x 设置
load_extras会读取目录文件并放到extras数组里。

if (!timeout_given) find_timeout();
如果没有给出超时时间，先去看看是不是恢复任务，会去寻找out_dir目录里的fuzzer_stats文件或in_dir目录里的fuzzer_stats，找里边的exec_timeout      : 的值，赋给exec_tmout timeout_given复制给3;

detect_file_args() 找参数里有没有@@，如果有，把"output/.cur_input"

check_binary()检查二进制文件
通过检查二进制文件里边的字符串，检查是否合法，并设置一些相关的变量，设置开始时间start_time = get_cur_time();

perform_dry_run()
运行一遍测试程序和测试用例。
  calibrate_case()
    init_forkserver()
      pipe(st_pipe)
      pipe(ctl_pipe)
    打开两个管道，
      forksrv_pid = fork();
    fork子进程，子进程会根据参数配置，限制一些内存，文件描述符数量如果低于200，设置成200。  dup2(dev_null_fd, 1);dup2(dev_null_fd, 2);把标准输出和标准错误输出设为忽略。如果指定了@@，标准输入也设为忽略。dup2(ctl_pipe[0], FORKSRV_FD)；dup2(st_pipe[1], FORKSRV_FD + 1；用FORKSRV_FD和FORKSRV_FD + 1分别指定ctl_pipe（描述符：fsrv_ctl_fd）和st_pipe（描述符：fsrv_st_fd），关掉用不到的父进程打开的描述符。设置afl的相关环境变量。父进程读取st_pipe的内容，如果不合规就waitpid，合规直接返回。
    write_to_testcase() 把内容写到output指定的之前使用符号链接的文件中。
    run_target()把prev_timed_out通过fsrv_ctl_fd传给子进程，把child_pid通过fsrv_st_fd读出来。
cull_queue()精简队列，

