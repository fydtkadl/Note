# **Open Memory**

ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9에서 애플리케이션의 .dex 파일을 로딩하는데 해당 부분을 후킹하면 원본 .dex 파일을 얻을 수 있다.

```python
# Tested at Note 5(Android 7.0) armv8

import frida
import sys
import binascii

def on_message(message, data):
    if message['type']=='send':
        dexFileDump = message['payload']
        lines = dexFileDump.split('n')
        dexFile = b''
        for line in lines:
            for i in range(2,18):

                dexFile += binascii.a2b_hex(line.split(' ')[i])
        f=open('classes.dex','wb')
        f.write(dexFile)
        f.close()
        print('[*] done!')

    else:
        print(message)

if __name__=="__main__":
    jscode = ''
    device = frida.get_usb_device()
    pid = device.spawn(["owasp.mstg.uncrackable1"])
    session = device.attach(pid)

    jscode = """
        var openmemory = Module.findExportByName('libart.so','_ZN3art7DexFile10OpenMemoryEPKhmRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_');

        function dumpAddr(addr, size) {
         if (addr.isNull())
          return;
         var buf = Memory.readByteArray(addr, size);
         send(hexdump(buf, { offset: false, length: size, header: false, ansi: false }));
        }

        Interceptor.attach(openmemory, {
            onEnter: function (args) {
              
                console.log('[*] openmemory addr: '+openmemory);
                
                var begin = this.context.x0;
                console.log("[*] magic : " + Memory.readUtf8String(begin));

                var address = parseInt(begin,16) + 0x20;
                var dex_size = Memory.readInt(ptr(address));

                console.log("[*] dex size :" + dex_size);

                dumpAddr(begin,dex_size);
            },
            onLeave: function (retval) {

            }
        });
    """

    script = session.create_script(jscode)

    script.load()
    script.on('message', on_message)
    device.resume(pid)
    sys.stdin.read()
```