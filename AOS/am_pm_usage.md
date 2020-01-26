# **am usage**

1. 액티비티 실행하는 방법
    * am start -a android.intent.action.MAIN -n 패키지명/액티비티 경로명
    * ex) am start -a android.intent.action.MAIN -n com.example.echo/com.example.echo.echodemo
1. 서비스 실행하는 방법
    * adb shell am startservice -n 패키지명/서비스경로명
    * ex) am startservice -n com.example.echo/com.example.echo.echoservice
1. broadcast 테스트하기
    * adb shell am broadcast -a "브로드캐스트명"
    * ex) adb shell am broadcast -a android.accounts.LOGIN_ACCOUNTS_CHANGED

 
# **pm usage**

pm (package manager)
1. 설치된 앱 확인
    * pm list package -f
1. 사용자의 이름을 확인합니다
    * pm list users
1. 모든 시스템 패키지들의 권한을 확인합니다
    * pm list permissions -d -g 
1. 특정 앱을 삭제합니다
    * pm uninstall com.example.MyApp
