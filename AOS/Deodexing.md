# **Deodexing**

odex를 dex로 재컴파일한 다음에 .apk에 classes.dex를 넣는 것을 deodexing이라고 한다.

1. /system/framwork를 pull
1. baksmali를 통해 deodexing  
  ex) java -jar baksmali.jar deodex app.odex -b framework/arm/boot.oat -a 28  
  -a : api  
  -b : framework/arm/boot.oat  
  -o : output (default: out)  

1. smali를 통해 classes.dex 생성  
  ex) java -jar smali.jar ass out -o classes.dex
1. .apk 에 7zip으로 압축파일 열기 후 드래그로 push