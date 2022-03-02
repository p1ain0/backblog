---
title: 高级I/O
date: 2021-09-02
tags: unix
---

## 非阻塞I/O

如果某些文件类型(如读管道、终端设备和网络设备)的数据并不存在，读操作可能会使调用者永远阻塞；

如果数据不能被相同的文件类型立即接受(如：管道中无空间、网路流控制)，写操作可能会使调用者永远阻塞；

在某些条件发生之前打开某些文件可能回发生阻塞(如要打开一个终端设备，需要先等待与之连接的调制解调器应答，又如若以只写模式打开FIFO，那么在没有其他进程已用读模式打开该FIFO时也要等待)；

对已经加上强制性记录锁的文件进行读写；

某些ioctl操作；

某些进程间通信函数。

非阻塞I/O使我们可以发出open、read和write这样的I/O操作，并使这些操作不会永远阻塞。如果这种操作不能完成，则调用立即出错返回，表示该操作如继续执行将阻塞。

对于一个给定的描述符，有两种为其指定非阻塞I/O的方法。

    1.如果调用open获得的描述符，则可以指定O_NONBLOCK标志。
    2.对于已经打开的一个描述符，则可调用fcntl，由该函数打开O_NONBLOCK文件状态标志。

## 记录锁

记录锁（record locking）的功能是：当第一个进程正在读或修改文件的某个部分时，使用记录锁可以阻止其他进程修改同一文件区。

fcntl记录锁：

```c++
#include <fcnt1.h>int fcnt1(int fd, int cmd, .../* struct flock *flockptr */);
```

返回值：若成功，依赖于cmd（见下），否则，返回−1对于记录锁，cmd是F_GETLK、F_SETLK或F_SETLKW。第三个参数（我们将调用flockptr）是一个指向flock结构的指针。

```c++
struct flock {
    short l_type;/* F_RDLCK(共享读锁), F_WRLCK（独占性写锁）, or F_UNLCK（解锁一个区域） */
    short l_whence;/* SEEK_SET, SEEK_CUR, or SEEK_END */
    off_t l_start;/* offset in bytes, relative to l_whence */
    off_t l_len;/* length, in bytes; 0 means lock to EOF */
    pid_t l_pid;/* returned with F_GETLK */
};
```

## I/O多路转接

果必须从两个描述符读，在这种情况下，我们不能在任一个描述符上进行阻塞读（read），否则可能会因为被阻塞在一个描述符的读操作上而导致另一个描述符即使有数据也无法处理。

为了使用这种技术，先构造一张我们感兴趣的描述符（通常都不止一个）的列表，然后调用一个函数，直到这些描述符中的一个已准备好进行I/O时，该函数才返回。poll、pselect和select这3个函数使我们能够执行I/O多路转接。在从这些函数返回时，进程会被告知哪些描述符已准备好可以进行I/O。

## 异步I/O

```c++
#include <aio.h>
int aio_read(struct aiocb *aiocb);
int aio_write(struct aiocb *aiocb);
int aio_fsync(int op, struct aiocb *aiocb);
int aio_error(const struct aiocb *aiocb);
ssize_t aio_return(const struct aiocb *aiocb);
int aio_suspend(const struct aiocb *const list[], int nent, const struct timespec *timeout);
int aio_cancel(int fd, struct aiocb *aiocb);
```

## 函数readv和writev

readv和writev函数用于在一次函数调用中读、写多个非连续缓冲区。有时也将这两个函数称为散布读（scatter read）和聚集写（gather write）。

```c++
#include <sys/uio.h>s
size_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
```

## 函数readn和writen

```c++
ssize_t readn(int fd, void *buf, size_t nbytes);
ssize_t writen(int fd, void *buf, size_t nbytes);
```

## 存储映射I/O

存储映射I/O（memory-mapped I/O）能将一个磁盘文件映射到存储空间中的一个缓冲区上，于是，当从缓冲区中取数据时，就相当于读文件中的相应字节。与此类似，将数据存入缓冲区时，相应字节就自动写入文件。这样，就可以在不使用read和write的情况下执行I/O。

```c++
#include <sys/mman.h>
void *mmap(void *addr, size_t len, int prot, int flag, int fd, off_t off);
int munmap(void *addr, size_t len)
```

返回值：若成功，返回映射区的起始地址；若出错，返回MAP_FAILED。

addr参数用于指定映射存储区的起始地址。通常将其设置为0，这表示由系统选择该映射区的起始地址。此函数的返回值是该映射区的起始地址。

fd参数是指定要被映射文件的描述符。在文件映射到地址空间之前，必须先打开该文件。

len参数是映射的字节数，

off是要映射字节在文件中的起始偏移量（有关off值的一些限制将在后面说明）。

prot参数指定了映射存储区的保护要求，可将prot参数指定为PROT_NONE，也可指PROT_READ、PROT_WRITE和PROT_EXEC的任意组合的按位或。对指定映射存储区的保护要求不能超过文件open模式访问权限。例如，若该文件是只读打开的，那么对映射存储区就不能指定PROT_WRITE。

    注意：子进程能通过fork继承存储映射区（因为子进程复制父进程地址空间，而存储映射区是该地址空间中的一部分），但是由于同样的原因，新程序则不能通过exec继承存储映射区。
    调用mprotect可以更改一个现有映射的权限。
