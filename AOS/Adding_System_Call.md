# **Adding System Call**

1. include/uapi/asm-generic/unistd.h 에서 System Call을 추가한다.

    ```c
    #define __NR_setenforce 278  // System Call 번호
    __SYSCALL(__NR_setenforce, sys_setenforce)

    #undef __NR_syscalls
    #define __NR_syscalls 279  // System Call 개수 
    ```

1. kernel 하위에 .c 파일을 생성한다. 예제로 setenforce를 enable/disable 가능한 System Call을 추가했다.
    
    ```c
    // setenforce.c
    #include <linux/unistd.h>
    #include <linux/kernel.h>
    #include <linux/sched.h>
    #include <linux/kern_levels.h>
    #include <linux/compat.h>
    #include <linux/selinux.h>

    extern int selinux_enforcing;
    extern void selnl_notify_setenforce(int val);
    extern void selinux_status_update_setenforce(int enforcing);

    asmlinkage long sys_setenforce(int val){
        selinux_enforcing = val;
        selnl_notify_setenforce(selinux_enforcing);
        selinux_status_update_setenforce(selinux_enforcing);
        return 0;
    } 
    ```

1. kernel 하위의 Makefile에서 obj-y 마지막에 .o 파일을 추가한다.
    
    ```
    obj-y     = fork.o exec_domain.o panic.o printk.o \
            cpu.o exit.o itimer.o time.o softirq.o resource.o \
            sysctl.o sysctl_binary.o capability.o ptrace.o timer.o user.o \
            signal.o sys.o kmod.o workqueue.o pid.o task_work.o \
            rcupdate.o extable.o params.o posix-timers.o \
            kthread.o wait.o sys_ni.o posix-cpu-timers.o mutex.o \
            hrtimer.o rwsem.o nsproxy.o srcu.o semaphore.o \
            notifier.o ksysfs.o cred.o \
            async.o range.o groups.o lglock.o smpboot.o setenforce.o
    ...
    ```

1. arch/arm64/include/asm/syscalls.h 에서 sys_setenforce 을 선언해준다.

    ```c
    ...
    #include <asm-generic/syscalls.h>
    asmlinkage long sys_setenforce(int val);
    ...
    ```

1. kernel build 후 NDK를 통해 추가한 System Call을 호출하는 바이너리 파일 샐성

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/syscall.h>
    #include <linux/unistd.h>
    #include <linux/kernel.h>
    #include <linux/sched.h>
    #include <unistd.h>

    #define __NR_setenforce 278

    int main(int argc,char* argv[]) {

            if(argc != 2){
                    printf("Usage : %s [0 - 1]\n",argv[0]);
                    exit(0);
            }

            int val;
            val = atoi(argv[1]);
            syscall(__NR_setenforce,val);
            return 0;
    }
    ```

1. 해당 파일을 통해 selinux enable/disable 가능

    ```
    bullhead:/data/local/tmp $ ./setenforce 1           
    bullhead:/data/local/tmp $ getenforce
    Enforcing
    bullhead:/data/local/tmp $ ./setenforce 0
    bullhead:/data/local/tmp $ getenforce
    Permissive
    ```