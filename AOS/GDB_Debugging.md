# **GDB Debugging**

1. ndk 다운로드
    * https://developer.android.com/ndk/downloads
1. /android-ndk-r20b/prebuilt/android-arm64/gdbserver를 android에 push
1. chmod로 권한을 부여한 후 gdbserver 실행
    * ./gdbserver :1234 --attach <pid_of_process>
1. adb 포트포워딩
    * adb forward tcp:1234 tcp:1234
1. /android-ndk-r20b/prebuilt/linux-x86_64/bin/gdb 실행 후 attach 
    * (gdb) target remote :1234
```
bs@bs-virtual-machine:~/Desktop/android/android-ndk-r20b/prebuilt/linux-x86_64/bin$ ./gdb
GNU gdb (GDB) 7.11
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word".
(gdb) target remote :1234
Remote debugging using :1234
Reading /system/bin/app_process64 from remote target...
warning: File transfers from remote targets can be slow. Use "set sysroot" to access files locally instead.
Reading /system/bin/app_process64 from remote target...
Reading symbols from target:/system/bin/app_process64...(no debugging symbols found)...done.
Reading /system/bin/linker64 from remote target...
Reading /system/lib64/libcutils.so from remote target...
Reading /system/lib64/libutils.so from remote target...
Reading /system/lib64/liblog.so from remote target...
Reading /system/lib64/libbinder.so from remote target...
Reading /system/lib64/libnativeloader.so from remote target...
Reading /system/lib64/libandroid_runtime.so from remote target...
Reading /system/lib64/libwilhelm.so from remote target...
Reading /system/lib64/libc++.so from remote target...
```
