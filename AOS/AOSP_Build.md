GingerBread 이상일 시 64비트 환경 필요
최소 200GB 이상의 디스크 공간(소스 다운로드용 ) + 150GB 여분의 공간(빌드 용)
최소 16GB RAM(swap)

Java 
sudo apt-get install openjdk-8-jdk

필요 패키지
sudo apt-get install git-core gnupg flex bison gperf build-essential zip curl zlib1g-dev gcc-multilib g++-multilib libc6-dev-i386 lib32ncurses5-dev x11proto-core-dev libx11-dev lib32z-dev libgl1-mesa-dev libxml2-utils xsltproc unzip

Repo
mkdir ~/bin
PATH=~/bin:$PATH
curl https://storage.googleapis.com/git-repo-downloads/repo > ~/bin/repo
chmod a+x ~/bin/repo

디렉토리 
mkdir android-7.1.1
cd android-7.1.1

git 연결
git config --global user.name "Your Name"
git config --global user.email "you@example.com"

android 기본에 repo 연결
repo init -u https://android.googlesource.com/platform/manifest

android branch 설정
repo init -u https://android.googlesource.com/platform/manifest -b android-7.1.2_r1

다운로드
repo sync -j4

repo sync

https://developers.google.com/android/drivers

driver 압축 풀면 .sh 생기는데 소스디렉토리에 넣고 실행


Build 

명령어 실행

source build/envsetup.sh
명령어 실행 후 항목이 나오는데, 그 중 자신의 기기에 맞는 항목 선택

lunch
make 실행

make
빌드가 잘되면… out/target/product/장치 모델/img 파일이 생성되었다는 것을 확인 할 수 있습니다.

플래싱
이제 플래싱을 하여야합니다.

플래싱은 커스텀한 롬 즉, 펌웨어를 핸드폰에 로딩시키는 과정이라고 생각하시면 됩니다.

fastboot 명령어를 치기위해서는 fastboot 패키지가 필요하니… 설치하세요.

fastboot flash boot out/target/product/<device>/boot.img
fastboot flash recovery out/target/product/<device>/recovery.img
fastboot flash system out/target/product/<device>/system.img
fastboot flash vendor out/target/product/<device>/vendor.img
fastboot flash userdata out/target/product/<device>/userdata.img
결과
원래는 ROM Name이라는 항목이 없는데, 그 부분을 추가하였고, 저의 이름이 들어가있는거를 볼 수 있습니다.


#[java Heap error날 경우]
Android source code compile error: “Try increasing heap size with java option '-Xmx<size>'”
$export JACK_SERVER_VM_ARGUMENTS="-Dfile.encoding=UTF-8 -XX:+TieredCompilation -Xmx4g"
$./prebuilts/sdk/tools/jack-admin kill-server
