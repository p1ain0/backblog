---
title: Java类加载机制
date: 2021-08-20
tags: Android
---

## JVM的类加载器包括3种

　　1）Bootstrap ClassLoader（引导类加载器）

　　C/C++代码实现的加载器，用于加载指定的JDK的核心类库，比如java.lang.、java.uti.等这些系统类。Java虚拟机的启动就是通过Bootstrap ，该Classloader在java里无法获取，负责加载/lib下的类。
　　2）Extensions ClassLoader（拓展类加载器）

　　Java中的实现类为ExtClassLoader，提供了除了系统类之外的额外功能，可以在java里获取，负责加载/lib/ext下的类。
　　3）Application ClassLoader（应用程序类加载器）

　　Java中的实现类为AppClassLoader，是与我们接触对多的类加载器，开发人员写的代码默认就是由它来加载，ClassLoader.getSystemClassLoader返回的就是它。

也可以自定义类加载器，只需要通过继承java.lang.ClassLoader类的方式来实现自己的类加载器即可。

加载顺序：

1. Bootstrap CLassloder
2. Extention ClassLoader
3. AppClassLoader

双亲委派机制：

双亲委派模式的工作原理的是;如果一个类加载器收到了类加载请求，它并不会自己先去加载，而是把这个请求委托给父类的加载器去执行，如果父类加载器还存在其父类加载器，则进一步向上委托，依次递归，请求最终将到达顶层的启动类加载器，如果父类加载器可以完成类加载任务，就成功返回，倘若父类加载器无法完成此加载任务，子加载器才会尝试自己去加载，这就是双亲委派模式，即每个儿子都不愿意干活，每次有活就丢给父亲去干，直到父亲说这件事我也干不了时，儿子自己想办法去完成，这个就是双亲委派。

why：

1）避免重复加载，如果已经加载过一次Class，可以直接读取已经加载的Class

2）更加安全，无法自定义类来替代系统的类，可以防止核心API库被随意篡改

类加载的时机：

1、隐式加载：

    创建类的实例
    访问类的静态变量，或者为静态变量赋值
    调用类的静态方法
    使用反射方式来强制创建某个类或接口对应的java.lang.Class对象
    初始化某个类的子类

2、显示加载：两者又有所区别

    使用LoadClass（）加载
    使用forName（）加载

1、装载：查找和导入Class文件

2、链接：其中解析步骤是可以选择的

    （a）检查：检查载入的class文件数据的正确性
    （b）准备：给类的静态变量分配存储空间
    （c）解析：将符号引用转成直接引用

3、初始化：即调用\<clinit\>函数，对静态变量，静态代码块执行初始化工作

## Android的类加载器

Android系统中与ClassLoader相关的一共有8个：

ClassLoader为抽象类；

BootClassLoader预加载常用类，单例模式。与Java中的BootClassLoader不同，它并不是由C/C++代码实现，而是由Java实现的；

BaseDexClassLoader是PathClassLoader、DexClassLoader、InMemoryDexClassLoader的父类，类加载的主要逻辑都是在BaseDexClassLoader完成的。

SecureClassLoader继承了抽象类ClassLoader，拓展了ClassLoader类加入了权限方面的功能，加强了安全性，其子类URLClassLoader是用URL路径从jar文件中加载类和资源。

其中重点关注的是PathClassLoader和DexClassLoader。

PathClassLoader是Android默认使用的类加载器，一个apk中的Activity等类便是在其中加载。

DexClassLoader可以加载任意目录下的dex/jar/apk/zip文件，比PathClassLoader更灵活，是实现插件化、热修复以及dex加壳的重点。

Android8.0新引入InMemoryDexClassLoader，从名字便可看出是用于直接从内存中加载dex。
