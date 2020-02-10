# **One gadget**

## **Install**

```
sudo apt install ruby
sudo gem install one_gadget
```

## **Usage**

```
$ one_gadget /lib/x86_64-linux-gnu/libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
