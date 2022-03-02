# 串（ADT）

## 定义

有来自字母表的字符所组成的有限序列。字符串就是由若干个字符由前至后所构成的一个线性序列。既然是linear线性，就可以用vector和list实现；但通常字符的种类不多，而串长往往很大。

### 几个关键概念

S[0, n) S[k]

#### 相等

S[0,n) = T[0,n) <==> 长度相等（n==m），且对应的字符均相同(S[i] = T[i])

#### 字串

S.substr(i,k) = S[i, i+k)

从S[i]起的连续k个字符

#### 前缀

S.prefix(k) = S.substr(0,k) = S[0,k)
亦即，S中最靠前的k个字符

#### 后缀

S.suffix(k) = S.substr(n-k, k) = S[n-k, n)
亦即，S中最靠后的k个字符

#### 空串

S[0,n=0),也是任何串的子串，前缀，后缀

## ADT作为一种抽象类型提供的功能接口

>length()
>charAt(i)
>substr(i,k)
>prefix(k)
>suffix(k)
>concat(T)
>equal(T)
>**indexOf(P)**

## 串匹配

### 什么是串匹配

### 具体功能要求

是否出现
出现位置
共几次出现
各出现在哪。

## 模式匹配

### 蛮力匹配

### KMP算法

