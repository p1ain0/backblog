---
title: python核心技术（二）
date: 2020-04-06
tags: python
---

## 一、Python对象的比较、拷贝

### 1.`'=='` VS `'is'`

等于（==）和 is 是 Python 中对象比较常用的两种方式。简单来说，`'=='`操作符比较对象之间的值是否相等；而`'is'`操作符比较的是对象的身份标识是否相等，即它们是否是同一个对象，是否指向同一个内存地址。

在 Python 中，每个对象的身份标识，都能通过函数 id(object) 获得。因此，`'is'`操作符，相当于比较对象之间的 ID 是否相等。使用id()函数可以查看对象的id。

- 比较操作符`'=='`表示比较对象间的值是否相等，而`'is'`表示比较对象的标识是否相等，即它们是否指向同一个内存地址。
- 比较操作符`'is'`效率优于`'=='`，因为`'is'`操作符无法被重载，执行`'is'`操作只是简单的获取对象的 ID，并进行比较；而`'=='`操作符则会递归地遍历对象的所有值，并逐一比较。

### 2.浅拷贝和深度拷贝

先来看浅拷贝。常见的浅拷贝的方法，是使用数据类型本身的构造器。

所谓深度拷贝，是指重新分配一块内存，创建一个新的对象，并且将原对象中的元素，以递归的方式，通过创建新的子对象拷贝到新对象中。因此，新对象和原对象没有任何关联。

Python 中以 copy.deepcopy() 来实现对象的深度拷贝。

- 浅拷贝中的元素，是原对象中子对象的引用，因此，如果原对象中的元素是可变的，改变其也会影响拷贝后的对象，存在一定的副作用。
- 深度拷贝则会递归地拷贝原对象中的每一个子对象，因此拷贝后的对象和原对象互不相关。另外，深度拷贝中会维护一个字典，记录已经拷贝的对象及其 ID，来提高效率并防止无限递归的发生。

## 二、参数传递

和其他语言不同的是，Python 中参数的传递既不是值传递，也不是引用传递，而是赋值传递，或者是叫对象的引用传递。这里的赋值或对象的引用传递，不是指向一个具体的内存地址，而是指向一个具体的对象。

- 如果对象是可变的，当其改变时，所有指向这个对象的变量都会改变。
- 如果对象不可变，简单的赋值只能改变其中一个变量的值，其余变量则不受影响。

## 三、装饰器

**所谓的装饰器，其实就是通过装饰器函数，来修改原函数的一些功能，使得原函数不需要修改。**

引入装饰器之前，我们首先一起来复习一下，必须掌握的函数的几个核心概念。

第一点，我们要知道，在 Python 中，函数是一等公民（first-class citizen），函数也是对象。我们可以把函数赋予变量，比如下面这段代码：

```
def func(message):
    print('Got a message: {}'.format(message))
    
send_message = func
send_message('hello world')
 
# 输出
Got a message: hello world
```

这个例子中，我们把函数 func() 赋予了变量 send_message，这样之后你调用 send_message，就相当于是调用函数 func()。

第二点，我们可以把函数当作参数，传入另一个函数中，比如下面这段代码：

```
def get_message(message):
    return 'Got a message: ' + message
 
 
def root_call(func, message):
    print(func(message))
    
root_call(get_message, 'hello world')
 
# 输出
Got a message: hello world
```

这个例子中，我们就把函数 get_message() 以参数的形式，传入了函数 root_call() 中然后调用它。

第三点，我们可以在函数里定义函数，也就是函数的嵌套。这里我同样举了一个例子：

```
def func(message):
    def get_message(message):
        print('Got a message: {}'.format(message))
    return get_message(message)
 
func('hello world')
 
# 输出
Got a message: hello world
```

这段代码中，我们在函数 func() 里又定义了新的函数 get_message()，调用后作为 func() 的返回值返回。

第四点，要知道，函数的返回值也可以是函数对象（闭包），比如下面这个例子：

```
def func_closure():
    def get_message(message):
        print('Got a message: {}'.format(message))
    return get_message
 
send_message = func_closure()
send_message('hello world')
 
# 输出
Got a message: hello world
```

这里，函数 func_closure() 的返回值是函数对象 get_message() 本身，之后，我们将其赋予变量 send_message，再调用 send_message(‘hello world’)，最后输出了`'Got a message: hello world'`。

### 简单的装饰器

简单的复习之后，我们接下来学习今天的新知识——装饰器。按照习惯，我们可以先来看一个装饰器的简单例子：

```
def my_decorator(func):
    def wrapper():
        print('wrapper of decorator')
        func()
    return wrapper
 
def greet():
    print('hello world')
 
greet = my_decorator(greet)
greet()
 
# 输出
wrapper of decorator
hello world
```

这段代码中，变量 greet 指向了内部函数 wrapper()，而内部函数 wrapper() 中又会调用原函数 greet()，因此，最后调用 greet() 时，就会先打印`'wrapper of decorator'`，然后输出`'hello world'`。

这里的函数 my_decorator() 就是一个装饰器，它把真正需要执行的函数 greet() 包裹在其中，并且改变了它的行为，但是原函数 greet() 不变。

事实上，上述代码在 Python 中有更简单、更优雅的表示：

```
def my_decorator(func):
    def wrapper():
        print('wrapper of decorator')
        func()
    return wrapper
 
@my_decorator
def greet():
    print('hello world')
 
greet()
```

这里的`@`，我们称之为语法糖，`@my_decorator`就相当于前面的`greet=my_decorator(greet)`语句，只不过更加简洁。因此，如果你的程序中有其它函数需要做类似的装饰，你只需在它们的上方加上`@decorator`就可以了，这样就大大提高了函数的重复利用和程序的可读性。

### 带有参数的装饰器

你或许会想到，如果原函数 greet() 中，有参数需要传递给装饰器怎么办？

一个简单的办法，是可以在对应的装饰器函数 wrapper() 上，加上相应的参数，比如：

```
def my_decorator(func):
    def wrapper(message):
        print('wrapper of decorator')
        func(message)
    return wrapper
 
 
@my_decorator
def greet(message):
    print(message)
 
 
greet('hello world')
 
# 输出
wrapper of decorator
hello world
```

不过，新的问题来了。如果我另外还有一个函数，也需要使用 my_decorator() 装饰器，但是这个新的函数有两个参数，又该怎么办呢？比如：

```
@my_decorator
def celebrate(name, message):
    ...
```

事实上，通常情况下，我们会把`*args`和`**kwargs`，作为装饰器内部函数 wrapper() 的参数。`*args`和`**kwargs`，表示接受任意数量和类型的参数，因此装饰器就可以写成下面的形式：

```
def my_decorator(func):
    def wrapper(*args, **kwargs):
        print('wrapper of decorator')
        func(*args, **kwargs)
    return wrapper
```

### 带有自定义参数的装饰器

其实，装饰器还有更大程度的灵活性。刚刚说了，装饰器可以接受原函数任意类型和数量的参数，除此之外，它还可以接受自己定义的参数。

举个例子，比如我想要定义一个参数，来表示装饰器内部函数被执行的次数，那么就可以写成下面这种形式：

```
def repeat(num):
    def my_decorator(func):
        def wrapper(*args, **kwargs):
            for i in range(num):
                print('wrapper of decorator')
                func(*args, **kwargs)
        return wrapper
    return my_decorator
 
 
@repeat(4)
def greet(message):
    print(message)
 
greet('hello world')
 
# 输出：
wrapper of decorator
hello world
wrapper of decorator
hello world
wrapper of decorator
hello world
wrapper of decorator
hello world
```

### 原函数还是原函数吗？

现在，我们再来看个有趣的现象。还是之前的例子，我们试着打印出 greet() 函数的一些元信息：

```
greet.__name__
## 输出
'wrapper'
 
help(greet)
# 输出
Help on function wrapper in module __main__:
 
wrapper(*args, **kwargs)
```

你会发现，greet() 函数被装饰以后，它的元信息变了。元信息告诉我们“它不再是以前的那个 greet() 函数，而是被 wrapper() 函数取代了”。

为了解决这个问题，我们通常使用内置的装饰器`@functools.wrap`，它会帮助保留原函数的元信息（也就是将原函数的元信息，拷贝到对应的装饰器函数里）。

```
import functools
 
def my_decorator(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('wrapper of decorator')
        func(*args, **kwargs)
    return wrapper
    
@my_decorator
def greet(message):
    print(message)
 
greet.__name__
 
# 输出
'greet'
```

### 类装饰器

前面我们主要讲了函数作为装饰器的用法，实际上，类也可以作为装饰器。类装饰器主要依赖于函数`__call_()`，每当你调用一个类的示例时，函数`__call__()`就会被执行一次。

我们来看下面这段代码：

```
class Count:
    def __init__(self, func):
        self.func = func
        self.num_calls = 0
 
    def __call__(self, *args, **kwargs):
        self.num_calls += 1
        print('num of calls is: {}'.format(self.num_calls))
        return self.func(*args, **kwargs)
 
@Count
def example():
    print("hello world")
 
example()
 
# 输出
num of calls is: 1
hello world
 
example()
 
# 输出
num of calls is: 2
hello world
 
...
```

这里，我们定义了类 Count，初始化时传入原函数 func()，而`__call__()`函数表示让变量 num_calls 自增 1，然后打印，并且调用原函数。因此，在我们第一次调用函数 example() 时，num_calls 的值是 1，而在第二次调用时，它的值变成了 2。

### 装饰器的嵌套

回顾刚刚讲的例子，基本都是一个装饰器的情况，但实际上，Python 也支持多个装饰器，比如写成下面这样的形式：

```python
@decorator1
@decorator2
@decorator3
def func():
    ...
```

它的执行顺序从里到外，所以上面的语句也等效于下面这行代码：

```python
decorator1(decorator2(decorator3(func)))
```

这样，`'hello world'`这个例子，就可以改写成下面这样：

```
import functools
 
def my_decorator1(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('execute decorator1')
        func(*args, **kwargs)
    return wrapper
 
 
def my_decorator2(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print('execute decorator2')
        func(*args, **kwargs)
    return wrapper
 
 
@my_decorator1
@my_decorator2
def greet(message):
    print(message)
 
 
greet('hello world')
 
# 输出
execute decorator1
execute decorator2
hello world
```

# 四、迭代器、生成器

## 迭代器

列表（list: [0, 1, 2]），元组（tuple: (0, 1, 2)），字典（dict: {0:0, 1:1, 2:2}），集合（set: set([0, 1, 2])）都是容器。所有的容器都是可迭代的（iterable）。迭代器（iterator）提供了一个 next 的方法。调用这个方法后，你要么得到这个容器的下一个对象，要么得到一个 StopIteration 的错误。你不需要像列表一样指定元素的索引，因为字典和集合这样的容器并没有索引一说。比如，字典采用哈希表实现，那么你就只需要知道，next 函数可以不重复不遗漏地一个一个拿到所有元素即可。

而可迭代对象，通过 iter() 函数返回一个迭代器，再通过 next() 函数就可以实现遍历。for in 语句将这个过程隐式化。

## 生成器

**生成器是懒人版本的迭代器**。

在迭代器中，如果我们想要枚举它的元素，这些元素需要事先生成。

声明一个迭代器很简单，`[i for i in range(100000000)]`就可以生成一个包含一亿元素的列表。每个元素在生成后都会保存到内存中，你通过代码可以看到，它们占用了巨量的内存，内存不够的话就会出现 OOM 错误。

不过，我们并不需要在内存中同时保存这么多东西，比如对元素求和，我们只需要知道每个元素在相加的那一刻是多少就行了，用完就可以扔掉了。

于是，生成器的概念应运而生，在你调用 next() 函数的时候，才会生成下一个变量。生成器在 Python 的写法是用小括号括起来，`(i for i in range(100000000))`，即初始化了一个生成器。

这样一来，你可以清晰地看到，生成器并不会像迭代器一样占用大量内存，只有在被使用的时候才会调用。而且生成器在初始化的时候，并不需要运行一次生成操作。

```python
def generator(k):
    i = 1
    while True:
        yield i ** k
        i += 1
 
gen_1 = generator(1)
gen_3 = generator(3)
print(gen_1)
print(gen_3)
 
def get_sum(n):
    sum_1, sum_3 = 0, 0
    for i in range(n):
        next_1 = next(gen_1)
        next_3 = next(gen_3)
        print('next_1 = {}, next_3 = {}'.format(next_1, next_3))
        sum_1 += next_1
        sum_3 += next_3
    print(sum_1 * sum_1, sum_3)
 
get_sum(8)
########## 输出 ##########
 
<generator object generator at 0x000001E70651C4F8>
<generator object generator at 0x000001E70651C390>
next_1 = 1, next_3 = 1
next_1 = 2, next_3 = 8
next_1 = 3, next_3 = 27
next_1 = 4, next_3 = 64
next_1 = 5, next_3 = 125
next_1 = 6, next_3 = 216
next_1 = 7, next_3 = 343
next_1 = 8, next_3 = 512
1296 1296
```



这段代码中，你首先注意一下 generator() 这个函数，它返回了一个生成器。

接下来的 yield 是魔术的关键。对于初学者来说，你可以理解为，函数运行到这一行的时候，程序会从这里暂停，然后跳出，不过跳到哪里呢？答案是 next() 函数。那么 `i ** k` 是干什么的呢？它其实成了 next() 函数的返回值。

这样，每次 next(gen) 函数被调用的时候，暂停的程序就又复活了，从 yield 这里向下继续执行；同时注意，局部变量 i 并没有被清除掉，而是会继续累加。我们可以看到 next_1 从 1 变到 8，next_3 从 1 变到 512。

迭代器是一个有限集合，生成器则可以成为一个无限集。我只管调用 next()，生成器根据运算会自动生成新的元素，然后返回给你，非常便捷。

再例如：给定一个 list 和一个指定数字，求这个数字在 list 中的位置。

```python
def index_generator(L, target):
    for i, num in enumerate(L):
        if num == target:
            yield i
 
print(list(index_generator([1, 6, 2, 4, 5, 2, 8, 6, 3, 2], 2)))
 
########## 输出 ##########
 
[2, 5, 9]
```

