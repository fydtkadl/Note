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

1. https://android.googlesource.com/kernel/ 에 접속하여 원하는 Kernel Source 다운도르
1. 

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


여기서 .img 받은 다음에 
<https://developers.google.com/android/images>

mkbootimg 설치

<https://github.com/osm0sis/mkbootimg>  

mkboot로 받은 boot.img unpack 후 
arch/arm64/boot/Image.gz-dtb 이미지로 바꾸고 repack

fastboot flash boot newboot.img로 flashing 후 부팅하면 성공!


**References**  
<https://source.android.com/setup/build/building-kernels-deprecated>
