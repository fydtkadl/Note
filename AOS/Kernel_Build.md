
필요 패키지 설치
$ sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get install openjdk-8-jdk git git-core gnupg flex bison gperf build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev libgl1-mesa-dev libxml2-utils xsltproc unzip make liblz4-tool libncurses5 python repo android-tools-adb android-tools-fastboot chrpath gawk texinfo libsdl1.2-dev whiptail diffstat cpio libssl-dev lzip -y


[Tool Chain]

git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9

git branch -a 명령으로 확인

git checkout [branch명] 

[Build]

git clone https://android.googlesource.com/kernel/msm

git branch -a 명령으로 확인

git checkout [branch명]


cd hikey-linaro
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-android-
make hikey_defconfig
make


[flash]


여기서 .img 받은 다음에 
<https://developers.google.com/android/images>

mkbootimg 설치

<https://github.com/osm0sis/mkbootimg>  

mkboot로 받은 boot.img unpack 후 
arch/arm64/boot/Image.gz-dtb 이미지로 바꾸고 repack

fastboot flash boot newboot.img로 flashing 후 부팅하면 성공!


**References**  
<https://source.android.com/setup/build/building-kernels-deprecated>