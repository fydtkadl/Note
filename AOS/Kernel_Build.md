# **Kernel Build**

## **Required Package Installation**

```
sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install openjdk-8-jdk git git-core gnupg flex bison gperf build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev libgl1-mesa-dev libxml2-utils xsltproc unzip make liblz4-tool libncurses5 python repo android-tools-adb android-tools-fastboot chrpath gawk texinfo libsdl1.2-dev whiptail diffstat cpio libssl-dev lzip -y
```

## **Cross Compiler Download**

1. https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9 에서 git clone을 통해 다운로드  
1. ./bin 경로를 PATH에 추가 

```
$ git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
$ cd aarch64-linux-android-4.9
$ git branch -a | grep nougat-mr1-release
  remotes/origin/nougat-mr1-release
$ git checkout remotes/origin/nougat-mr1-release -b remotes/origin/nougat-mr1-release
$ cd ./bin
$ export PATH=$PATH:`pwd`
```

## **Build Kernel**

1. https://android.googlesource.com/kernel/ 에 접속하여 원하는 Kernel Source clone
1. 원하는 branch 생성

```
$ git clone https://android.googlesource.com/kernel/msm
$ git branch -a | grep bullhead-3.10-nougat-mr1
  remotes/origin/android-msm-bullhead-3.10-nougat-mr1
$ git checkout remotes/origin/android-msm-bullhead-3.10-nougat-mr1 -b remotes/origin/android-msm-bullhead-3.10-nougat-mr1
```

build.sh 파일 생성 후 실행하여 Kernel Build

```
#!/bin/bash
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-
make bullhead_defconfig
make
```

## **Flash**

1. mkbootimg 설치 후 PATH 설정

    * <https://github.com/xiaolu/mkbootimg_tools.git>  

1. Factory image 다운로드

    * <https://developers.google.com/android/images>

1. boot.img unpacking

    ```
    $ mkboot boot.img boot_dir
    Unpack & decompress boot.img to boot_dir
    kernel         : kernel
    ramdisk        : ramdisk
    page size      : 4096
    kernel size    : 10817210
    ramdisk size   : 1506510
    base           : 0x00000000
    kernel offset  : 0x00008000
    ramdisk offset : 0x02000000
    tags offset    : 0x01e00000
    cmd line       : console=ttyHSL0,115200,n8 androidboot.hardware=bullhead boot_cpus=0-5 lpm_levels.sleep_disabled=1 msm_poweroff.download_mode=0 buildvariant=user
    ramdisk is gzip format.
    Unpack completed.
    ```
1. kernel의 arch/arm64/boot/ 디렉토리에 Image.gz-dtb를 boot_dir/kernel로 변경

    ```
    $ ls
    dts  Image  Image.gz  Image.gz-dtb  install.sh  Makefile  wrapper
    $ ls
    img_info  kernel <- ramdisk  ramdisk.packed
    ```

1. 새로운 newboot.img 생성

    ```
    $ mkboot boot_dir newboot.img
    mkbootimg from boot_dir/img_info.
    kernel         : kernel
    ramdisk        : new_ramdisk
    page size      : 4096
    kernel size    : 10817210
    ramdisk size   : 1506565
    base           : 0x00000000
    kernel offset  : 0x00008000
    ramdisk offset : 0x02000000
    tags offset    : 0x01e00000
    cmd line       : console=ttyHSL0,115200,n8 androidboot.hardware=bullhead boot_cpus=0-5 lpm_levels.sleep_disabled=1 msm_poweroff.download_mode=0 buildvariant=user
    ramdisk is gzip format.
    Kernel size: 10817210, new ramdisk size: 1506565, newboot.img: 12328960.
    newboot.img has been created.
    ...
    ```

1. fastboot flash boot newboot.img로 Flash

    ```
    $ sudo fastboot flash boot newboot.img 
    target reported max download size of 536870912 bytes
    sending 'boot' (12040 KB)...
    OKAY [  1.053s]
    writing 'boot'...
    OKAY [  0.106s]
    finished. total time: 1.160s
    ```
1. dmesg로 변조된 start_kernel() 함수 확인

    ```
    $ sudo adb shell
    bullhead:/ $ dmesg | grep Modulated
    [    0.000000] Modulated Kernel!!!!!
    ```

**References**  
<https://source.android.com/setup/build/building-kernels-deprecated>
