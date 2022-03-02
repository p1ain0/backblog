# Emacs

## Linux Mac

安装完emacs后

```shell
git clone --depth 1 https://github.com/hlissner/doom-emacs ~/.emacs.d
~/.emacs.d/bin/doom install
```

### pyenv

```shell
sudo apt-get install git gcc make openssl libssl-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev
git clone https://github.com/pyenv/pyenv.git ~/.pyenv
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.zshrc
pyenv install 3.7.9
pyenv global 3.7.9
```

## Windows

安装完emacs后设置环境变量。

```dos
git clone --depth 1 https://github.com/hlissner/doom-emacs ~/.emacs.d
~/.emacs.d/bin/doom install
```

```dos
mklink /j "C:\Users\USER\.emacs.d" "C:\Users\USER\AppData\Roaming\.emacs.d"
```

安装图标
在Emacs中安装字体，键入M-x（Alt + x），并写如下：

```dos
all-the-icons-install-fonts
```

### Some Emacs hacking ideas

It is very easy to use Emacs to interactive with Windows’s programs, such as browsing the URL with Chrome, open the PDF file with Acrobat Reader DC, open the current file with default program, launch explorer.exe, etc. Here are some ideas:

### Browser URL with default browser

```lisp
(defun wsl-browse-url-xdg-open (url &optional ignored)
  (interactive (browse-url-interactive-arg "URL: "))
  (shell-command-to-string (concat "explorer.exe " url)))
(advice-add #'browse-url-xdg-open :override #'wsl-browse-url-xdg-open)
```

### If you a calibredb user, you can add the following advice to open the PDF/EPUB with windows default programs

```lisp
;; calibredb
(defun wslcalibredb-open-with-default-tool (filepath)
  (shell-command-to-string
   (concat "cd " (shell-quote-argument (file-name-directory (expand-file-name filepath))) " && "
           (concat "cmd.exe /C start '' \"${@//&/^&}\" " (shell-quote-argument (file-name-nondirectory filepath))))))
(advice-add #'calibredb-open-with-default-tool :override #'wslcalibredb-open-with-default-tool)
```

### Open the file with windows default programs or reveal it in explorer

```lisp
;;;###autoload
(defmacro wsl--open-with (id &optional app dir)
  `(defun ,(intern (format "wsl/%s" id)) ()
     (interactive)
     (wsl-open-with ,app ,dir)))

(defun wsl-open-with (&optional app-name path)
  "Send PATH to APP-NAME on WSL."
  (interactive)
  (let* ((path (expand-file-name
                (replace-regexp-in-string
                 "'" "\\'"
                 (or path (if (derived-mode-p 'dired-mode)
                              (dired-get-file-for-visit)
                            (buffer-file-name)))
                 nil t)))
         (command (format "%s `wslpath -w %s`" (shell-quote-argument app-name) path)))
    (shell-command-to-string command)))

(wsl--open-with open-in-default-program "explorer.exe" buffer-file-name)
(wsl--open-with reveal-in-explorer "explorer.exe" default-directory)
```

```dos
M-x wsl/open-in-default-program
M-x wsl/reveal-in-explorer
```

## dired(directory editor)使用

spc o p 打开文件列表在侧边栏

在文件目录上浏览文件时：
shift-9 可以切换目录样式
M 可以改变文件的属性
O 可以改变文件所有者
/ 选择目录
T 反向选择
U 选择所有的文件
m 选择单个文件
u 撤销所有选择

ctrl-w v分割屏幕
ctrl-w w在屏幕之间切换
C 可以复制文件
x 删除文件
R 移动文件

（设置dired-dwim-target 为 true）
spc o -