---
title: 遇到hexo莫名其妙的bug
date: 2021-09-09 13:20:25
tags:
---

最近blog换了hexo，遇到一些坑，记录下。图片就是不显示，遂看看是哪里出了问题用浏览器的查看元素查看图片的位置，发现图片的引用路径里不知道为啥多了个 `/.io//`,百度谷歌后无果，提了个issue没人理我。然后想着写个脚本给改过来。就是每次generate后都要执行一遍，有点麻烦。不过图片显示的问题解决了。脚本如下：

```python
import os

def modify(fd):
    html = fd.read()
    html = html.decode("utf-8")
    s = html.find('<img src="/.io//')
    print(s)
    html2 = html.replace('<img src="/.io//', '<img src="')
    fd.seek(0, 0)
    fd.write(html2.encode("utf-8"))

    

def main():
    for root, dirs, files in os.walk("./public/"):
        for file in files:
            fname = os.path.join(root, file)
            if (file == "index.html"):
                #print(fname)
                fd = open(fname, "rb+")
                modify(fd)
                fd.close()

if __name__ == "__main__":
    main()
```
