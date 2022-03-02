# VIM

## Basic Navigation

hjkl
x删除光标下方的单个字符
zz会使光标居中，ZZ取消居中
w单词跳跃，b向前跳跃
dd删除一行
yy复制，p粘贴在下行，P粘贴在上行

v-visual模式，可以选择文本删除复制粘贴
:reg 历史操作记录

insert mode

i left side of cursor
a right side of cursor
I 行首插入
A 行尾插入
o 下方插入一行
O 上方插入一行

## 配置文件

shift v 6j 选中向下的六行

set scrolloff=8 高于8行低于8行自动滚动
set number
set relativenumber(rnu)
set cursorline          //突出显示当前行
set ruler               //打开状态栏标尺

set tabstop=4 softtabstop=4
set shiftwidth=4
set expandtab
set smartindent
colorscheme Crlt + D
set backspace=indent,eol,start


### Remap

let mapleader = " " //我有一个特别的键，我想按一下
nnoremap <leader>pv:Vex<CR> //n代表你所处的模式 i v c t; nore非递归的；map映射

### Marks

echo stdpath("config")

### some useful commands

set hls ic //高亮显示所有搜索匹配
nohls

### Macros

按下q加字母录制Macros，再次按q退出

### Register

:reg

### Horizontal Movement

_ 移动到改行第一个字符处
0 移动到行首
$ 移动到行尾
D 删除
C 删除并编辑
S 删除单个字符
f 
, 
; 
t 
F 
T 

## nvim配置

https://neovim.io

~/.config/nvim/init.vim

1.Basic 

[ ] enhance editor

[ ] plugin manager vim-plug

[ ] theme vsdark

[ ] file explorer nerdtree

[ ] file finder LeaderF

2.LSP(language server photocol)

coc.nvim

[ ] enhance highlight vim-lsp-cxx-hightlight

[ ] completion

[ ] jump

3.DAP(Debug Adapter Protocol)

Vimspector插件

[ ] debug

:CocInstall coc-pyright

:checkpath



.vimspector.json:

```
{
  "configurations": {
    "Launch": {
      "adapter": "CodeLLDB",
      "configuration": {
        "request": "launch",
        "program": "${workspaceFolder}/test",
        "cwd": "${workspaceFolder}",
        "args": [ ],
        "environment": [ ],
        "externalConsole": true,
        "MIMode": "lldb"
      }
    }
  }
}

{
  "configurations": {
    "run": {
      "adapter": "debugpy",
      "configuration": {
        "request": "launch",
        "type": "python",
        "cwd": "${workspaceFolder}",
        "program": "${file}",
        "stopOnEntry": true,
        "args": [],
        "console": "integratedTerminal"
      },
      "breakpoints": {
        "exception": {
          "raised": "N",
          "uncaught": ""
        }
      }
    }
  }
}
```

