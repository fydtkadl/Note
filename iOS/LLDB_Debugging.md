# **LLDB Debugging**

LLDB 를 이용한 리모트 디버깅 간략 정리



출처 원문 : http://versprite.com/og/ios-reverse-engineering-part-one-configuring-lldb/



iOS 8.4 버전으로 넘어오면서 현재 GDB가 정상 동작하지 않는다.(직접 컴파일 해보진 않았다)



실행은 되지만 디버깅 시 뭔가 오류가 발생하며 제대로 동작하지 않으므로 대안으로 LLDB 를 사용할 수 있다.

(몇몇 고수들은 LLDB가 더 좋다는 사람도 있다)





        # hdiutil attach /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/

           DeviceSupport/8.0\\(12A365\)/DeveloperDiskImage.dmg



        # cp /Volumes/DeveloperDiskImage/usr/bin/debugserver /Users/hyunmini/

      

        # vi entitlements.plist



<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/ PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.springboard.debugapplications</key> <true/>
    <key>run-unsigned-code</key>
    <true/>
    <key>get-task-allow</key>
    <true/>
    <key>task_for_pid-allow</key>
    <true/>
</dict>
</plist>




# codesign -s - --entitlements entitlements.plist -f debugserver



#  sftp  root@x.x.x.x  

#>  put debugserver

# exit



여기까지 debugserver 를 업로드 하는 과정이다. 이제 iOS 디바이스에서 디버그서버를 실행하고 대기 한 뒤 디버거로 붙으면 된다. 





=========================

# iOS 디바이스에서

=========================

# ps -ef | grep  [process name]      // pid 확인

# ./debugserer *:7777 --attach=[pid]     // debugserver 실행





=========================

# MAC 에서

=========================

(lldb) platform select remote-ios             // 디버깅 플랫폼 지정

(lldb) process connect connect://192.168.20.107:7777            // debugserver 에 접속





이제부터 디버깅을 시작하면 된다. 



(lldb) b objc_msgSend



(lldb) c



(lldb) register read

**References**  
<https://hyunmini.tistory.com/71>
