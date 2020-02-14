# **Frida Cheat Sheet**

### **Python Building**

```python
# Python
import frida
import sys

def on_message(message, data):
    if message['type']=='send':
        print(message['payload'])
    else:
        print(message)

if __name__=="__main__":

    device = frida.get_usb_device()
    pid = device.spawn(["APP_NAME"])
    session = device.attach(pid)

    jscode = """

    """

    script = session.create_script(jscode)

    script.load()
    script.on('message', on_message)
    device.resume(pid)
    sys.stdin.read()
```

### **SSL Pinning Bypass**

```js
// SSL Pinning Bypass 
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");

    var ApiClient = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    ApiClient.checkTrustedRecursive.implementation = function(arg1,arg2,arg3,arg4,arg5,arg6) {
        var k = array_list.$new();
        return k;
    }
});
```

### **Enumerate Loaded Class**

```js
// Enumerate Loaded Class
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            console.log(className);
        },
        onComplete: function() {}
    });
});
```

### **Enumerate Imports**

```js
// Enumerate Imports
Module.enumerateImports("%s", {
    onMatch: function(imp){
      console.log('Module type: ' + imp.type + ' - Name: ' + imp.name + ' - Module: ' + imp.module + ' - Address: ' + imp.address.toString());
    }, 
    onComplete: function(){}
});
```

### **Context Hooking**

```js
// Context
var address = 0x00003446;

function hook(){
    // .so Address
    var p_foo = Module.findBaseAddress('libfoo.so');
    console.log("libfoo.so @ " + p_foo.toString());
    var target_address = p_foo.add(address);
    console.log("target_Address @ " + target_address.toString());
    Interceptor.attach(target_address, {
        onEnter: function (args) {
        console.log("onEnter() target_Address");
        console.log("Context : " + JSON.stringify(this.context));
        var ecx = this.context.ecx;
        console.log("ecx:"+ecx);
        console.log(hexdump(ecx,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
        var ebx = this.context.ebx;
        console.log("ebx:"+ebx);
        console.log(hexdump(ebx,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
         var esi = this.context.esi;
        console.log("esi:"+esi);
        console.log(hexdump(esi,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
        var edi = this.context.edi;
        console.log("edi:"+edi);
        console.log(hexdump(edi,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
        var ebp = this.context.ebp;
        console.log("ebp:"+ebp);
        console.log(hexdump(ebp,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
        var esp = this.context.esp;
        console.log("esp:"+esp);
        console.log(hexdump(esp,{
            offset: 0,
            length: 24,
            header: false,
            ansi:false
        }));
     },
     onLeave: function (retval) {
        console.log(retval);
     }
    
    });
}
```

### **Constructor Hook**

```js
// Constructor Hook
Java.perform(function() { 
    console.log();

    var ZXVpnAdd$SecuwayServiceConnection = Java.use('com.spo.npa_util.ZXVpnAdd$SecuwayServiceConnection');

    ZXVpnAdd$SecuwayServiceConnection.$init.overload('com.spo.npa_util.ZXVpnAdd').implementation = function(arg0) {
        console.log("arg0 : "+arg0);
        return this.$init(arg0);
    };
});
```

### **Bytes Control**

```js
// Bytes Control
function hexToBytes(hex) {
	for (var bytes = [], c = 0; c < hex.length; c += 2)
	bytes.push(parseInt(hex.substr(c, 2), 16));
	return bytes;
}

function bytesToHex(bytes) {
	for (var hex = [], i = 0; i < bytes.length; i++) { hex.push(((bytes[i] >>> 4) & 0xF).toString(16).toUpperCase());
		hex.push((bytes[i] & 0xF).toString(16).toUpperCase());
		hex.push(" ");
	}
	return hex.join("");
}
```

### **Stack Trace**

```js
// StackTrace
var ThreadDef = Java.use('java.lang.Thread');
var ThreadObj = ThreadDef.$new();

function stackTrace() {
   var stack = ThreadObj.currentThread().getStackTrace();
   for (var i = 0; i < stack.length; i++) {
      console.log(i + " => " + stack[i].toString());
   }
   //console.log("-------------------------------------");
}

```

### **Type Casting**

```js
// Type Casting
var JsonObject = Java.use("com.google.gson.JsonObject");
JsonObjectInstance = JsonObject.$new();

var decrypt = '{"resultType":"SUCCESS","success":{"result":1,"seqno":"3341556168644000587","otp":"0000","valid":1,"arsCallType":"OUT","carrier":"KT"}}'
decrypt = Java.cast(decrypt,JsonObject);
```

### **Print Runtime String**

```js
// Print Runtime String
Java.perform(function() {
  ['java.lang.StringBuilder', 'java.lang.StringBuffer'].forEach(function(clazz, i) {
    console.log('[?] ' + i + ' = ' + clazz);
    var func = 'toString';
    Java.use(clazz)[func].implementation = function() {
      var ret = this[func]();
      if (ret.indexOf('') != -1) {
        // print stacktrace if return value contains specific string
        Java.perform(function() {
          var jAndroidLog = Java.use("android.util.Log"), jException = Java.use("java.lang.Exception");
          console.log( jAndroidLog.getStackTraceString( jException.$new() ) );
        }); 
      }   
      send('[' + i + '] ' + ret);
      return ret;
    }   
  }); 
});
```

### **Create New Instance**

```js
// New Instance
var JsonParser = Java.use("com.google.gson.JsonParser");
var JsonParserInstance = JsonParser.$new();

Java.use("java.lang.Boolean").$new(true)
```

### **Instance Hooking**

```js
// Instance Hook
setImmediate(function() {
    console.log("[*] Starting script");
    Java.perform(function () {

        Java.choose("android.view.View", { 
             
             "onMatch":function(instance){
                  console.log("[*] Instance found: " + instance.toString());
             },

             "onComplete":function() {
                  console.log("[*] Finished heap search")
             }
        });

    });
});
```


### **Library Hooking**

```js
// Library Hook
Interceptor.attach(Module.findExportByName(null,"dlopen"),{
    onEnter: function(args) {
        this.soName = Memory.readCString(args[0]);
        console.log("[*] Loading " + this.soName);
        },
        onLeave: function(retval) {
            if(this.soName.indexOf("liba3030.so") != -1){
                console.log("t[+] " + this.soName + "Hooking.....");
                Interceptor.attach(Module.findExportByName("liba3030.so", "a3032"), {
                    onEnter: function(args){
                    console.log("tt[+] a3032 onEnter Success");   
          },
               onLeave: function(retval){
                   console.log("tt[+] a3032 onLeave Success");
                    retval.replace(0);
                    console.log("tt[!] Congratulation!! Root Detected ByPass Success :-D");
        }
            });
        }
    }          
});
```


### **Memory Scanning**

```js
// Memory Scan
Java.perform(function () {

function dumpAddr(addr, size) {
 if (addr.isNull())
  return;
 var buf = Memory.readByteArray(addr, size);
 console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
}

console.log('[*] Hooking');
 var ranges = Process.enumerateRanges('rw-');
 for (var idx in ranges) {
  // access token
  Memory.scan(ranges[idx].base, ranges[idx].size, '73 74 65 61 6c 69 65 6e', {
   onMatch: function (address, size) {
    console.log('[+] Pattern Found At '+address);
    dumpAddr(address, size);
  	address.writeByteArray([0x67,0x67,0x67,0x67,0x67,0x67,0x67,0x67]);
	dumpAddr(address, size);
   },
   onError: function () {
    
   },
   onComplete: function () {
    
   }
  });
 };
});
```

## **File System Access Hook**
```js
/**
It should be launch earlier in order to be aware of a maximun 
quantity of file descriptors.


@author @FrenchYeti
*/
Java.perform(function() {

    // ============= Config
    var CONFIG = {
        // if TRUE enable data dump 
        printEnable: true,
        // if TRUE enable libc.so open/read/write hook
        printLibc: false,
        // if TRUE print the stack trace for each hook
        printStackTrace: false,
        // to filter the file path whose data want to be dumped in ASCII 
        dump_ascii_If_Path_contains: [".log", ".xml", ".prop"],
        // to filter the file path whose data want to be NOT dumped in hexdump (useful for big chunk and excessive reads) 
        dump_hex_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"],
        // to filter the file path whose data want to be NOT dumped fron libc read/write (useful for big chunk and excessive reads) 
        dump_raw_If_Path_NOT_contains: [".png", "/proc/self/task", "/system/lib", "base.apk", "cacert"]
    }

    // =============  Keep a trace of file descriptor, path, and so
    var TraceFD = {};
    var TraceFS = {};
    var TraceFile = {};
    var TraceSysFD = {};


    // ============= Get classes
    var CLS = {
        File: Java.use("java.io.File"),
        FileInputStream: Java.use("java.io.FileInputStream"),
        FileOutputStream: Java.use("java.io.FileOutputStream"),
        String: Java.use("java.lang.String"),
        FileChannel: Java.use("java.nio.channels.FileChannel"),
        FileDescriptor: Java.use("java.io.FileDescriptor"),
        Thread: Java.use("java.lang.Thread"),
        StackTraceElement: Java.use("java.lang.StackTraceElement"),
        AndroidDbSQLite: Java.use("android.database.sqlite.SQLiteDatabase")
    };
    var File = {
        new: [
            CLS.File.$init.overload("java.io.File", "java.lang.String"),
            CLS.File.$init.overload("java.lang.String"),
            CLS.File.$init.overload("java.lang.String", "java.lang.String"),
            CLS.File.$init.overload("java.net.URI"),
        ]
    };
    var FileInputStream = {
        new: [
            CLS.FileInputStream.$init.overload("java.io.File"),
            CLS.FileInputStream.$init.overload("java.io.FileDescriptor"),
            CLS.FileInputStream.$init.overload("java.lang.String"),
        ],
        read: [
            CLS.FileInputStream.read.overload(),
            CLS.FileInputStream.read.overload("[B"),
            CLS.FileInputStream.read.overload("[B", "int", "int"),
        ],
    };
    var FileOuputStream = {
        new: [
            CLS.FileOutputStream.$init.overload("java.io.File"),
            CLS.FileOutputStream.$init.overload("java.io.File", "boolean"),
            CLS.FileOutputStream.$init.overload("java.io.FileDescriptor"),
            CLS.FileOutputStream.$init.overload("java.lang.String"),
            CLS.FileOutputStream.$init.overload("java.lang.String", "boolean")
        ],
        write: [
            CLS.FileOutputStream.write.overload("[B"),
            CLS.FileOutputStream.write.overload("int"),
            CLS.FileOutputStream.write.overload("[B", "int", "int"),
        ],
    };



    // ============= Hook implementation

    File.new[1].implementation = function(a0) {
        prettyLog("[Java::File.new.1] New file : " + a0);

        var ret = File.new[1].call(this, a0);
        var f = Java.cast(this, CLS.File);
        TraceFile["f" + this.hashCode()] = a0;


        return ret;
    }
    File.new[2].implementation = function(a0, a1) {
        prettyLog("[Java::File.read.2] New file : " + a0 + "/" + a1);

        var ret = File.new[2].call(this, a0, a1);;
        var f = Java.cast(this, CLS.File);
        TraceFile["f" + this.hashCode()] = a0 + "/" + a1;

        return ret;
    }


    FileInputStream.new[0].implementation = function(a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null) {
            var p = file.getAbsolutePath();
            if (p !== null)
                fname = TraceFile["f" + file.hashCode()] = p;
        }
        if (fname == null)
            fname = "[unknow]"

        prettyLog("[Java::FileInputStream.new.0] New input stream from file (" + fname + "): ");

        var fis = FileInputStream.new[0].call(this, a0)
        var f = Java.cast(this, CLS.FileInputStream);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);

        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }



    FileInputStream.read[1].implementation = function(a0) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        var b = Java.array('byte', a0);

        prettyLog("[Java::FileInputStream.read.1] Read from file,offset (" + fname + "," + a0 + "):\n" +
            prettyPrint(fname, b));

        return FileInputStream.read[1].call(this, a0);
    }
    FileInputStream.read[2].implementation = function(a0, a1, a2) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        var b = Java.array('byte', a0);

        prettyLog("[Java::FileInputStream.read.2] Read from file,offset,len (" + fname + "," + a1 + "," + a2 + ")\n" +
            prettyPrint(fname, b));

        return FileInputStream.read[2].call(this, a0, a1, a2);
    }



    // =============== File Output Stream ============



    FileOuputStream.new[0].implementation = function(a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null)
            fname = "[unknow]<File:" + file.hashCode() + ">";


        prettyLog("[Java::FileOuputStream.new.0] New output stream to file (" + fname + "): ");

        var fis = FileOuputStream.new[0].call(this, a0);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }

    FileOuputStream.new[1].implementation = function(a0) {
        var file = Java.cast(a0, CLS.File);
        var fname = TraceFile["f" + file.hashCode()];

        if (fname == null)
            fname = "[unknow]";


        prettyLog("[Java::FileOuputStream.new.1] New output stream to file (" + fname + "): \n");

        var fis = FileOuputStream.new[1].call(this, a0);

        TraceFS["fd" + this.hashCode()] = fname;

        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);

        TraceFD["fd" + fd.hashCode()] = fname;

        return fis;
    }

    FileOuputStream.new[2].implementation = function(a0) {
        var fd = Java.cast(a0, CLS.FileDescriptor);
        var fname = TraceFD["fd" + fd.hashCode()];

        if (fname == null)
            fname = "[unknow]";


        prettyLog("[Java::FileOuputStream.new.2] New output stream to FileDescriptor (" + fname + "): \n");
        var fis = FileOuputStream.new[1].call(this, a0)

        TraceFS["fd" + this.hashCode()] = fname;

        return fis;
    }
    FileOuputStream.new[3].implementation = function(a0) {
        prettyLog("[Java::FileOuputStream.new.3] New output stream to file (str=" + a0 + "): \n");

        var fis = FileOuputStream.new[1].call(this, a0)

        TraceFS["fd" + this.hashCode()] = a0;
        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = a0;

        return fis;
    }
    FileOuputStream.new[4].implementation = function(a0) {
        prettyLog("[Java::FileOuputStream.new.4] New output stream to file (str=" + a0 + ",bool): \n");

        var fis = FileOuputStream.new[1].call(this, a0)
        TraceFS["fd" + this.hashCode()] = a0;
        var fd = Java.cast(this.getFD(), CLS.FileDescriptor);
        TraceFD["fd" + fd.hashCode()] = a0;

        return fis;
    }



    FileOuputStream.write[0].implementation = function(a0) {
        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;

        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        prettyLog("[Java::FileOuputStream.write.0] Write byte array (" + fname + "):\n" +
            prettyPrint(fname, a0));

        return FileOuputStream.write[0].call(this, a0);
    }
    FileOuputStream.write[1].implementation = function(a0) {

        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
        }
        if (fname == null)
            fname = "[unknow]";

        prettyLog("[Java::FileOuputStream.write.1] Write int  (" + fname + "): " + a0);


        return FileOuputStream.write[1].call(this, a0);
    }
    FileOuputStream.write[2].implementation = function(a0, a1, a2) {

        var fname = TraceFS["fd" + this.hashCode()];
        var fd = null;
        if (fname == null) {
            fd = Java.cast(this.getFD(), CLS.FileDescriptor);
            fname = TraceFD["fd" + fd.hashCode()]
            if (fname == null)
                fname = "[unknow], fd=" + this.hashCode();
        }

        prettyLog("[Java::FileOuputStream.write.2] Write " + a2 + " bytes from " + a1 + "  (" + fname + "):\n" +
            prettyPrint(fname, a0));

        return FileOuputStream.write[2].call(this, a0, a1, a2);
    }

    // native hooks    
    Interceptor.attach(
        Module.findExportByName("libc.so", "read"), {
            // fd, buff, len
            onEnter: function(args) {
                if (CONFIG.printLibc === true) {
                    var bfr = args[1],
                        sz = args[2].toInt32();
                    var path = (TraceSysFD["fd-" + args[0].toInt32()] != null) ? TraceSysFD["fd-" + args[0].toInt32()] : "[unknow path]";

                    prettyLog("[Libc::read] Read FD (" + path + "," + bfr + "," + sz + ")\n" +
                        rawPrint(path, Memory.readByteArray(bfr, sz)));
                }
            },
            onLeave: function(ret) {

            }
        }
    );

    Interceptor.attach(
        Module.findExportByName("libc.so", "open"), {
            // path, flags, mode
            onEnter: function(args) {
                this.path = Memory.readCString(args[0]);
            },
            onLeave: function(ret) {
                TraceSysFD["fd-" + ret.toInt32()] = this.path;
                if (CONFIG.printLibc === true)
                    prettyLog("[Libc::open] Open file '" + this.path + "' (fd: " + ret.toInt32() + ")");
            }
        }
    );


    Interceptor.attach(
        Module.findExportByName("libc.so", "write"), {
            // fd, buff, count
            onEnter: function(args) {
                if (CONFIG.printLibc === true) {
                    var bfr = args[1],
                        sz = args[2].toInt32();
                    var path = (TraceSysFD["fd-" + args[0].toInt32()] != null) ? TraceSysFD["fd-" + args[0].toInt32()] : "[unknow path]";

                    prettyLog("[Libc::write] Write FD (" + path + "," + bfr + "," + sz + ")\n" +
                        rawPrint(path, Memory.readByteArray(bfr, sz)));
                }
            },
            onLeave: function(ret) {

            }
        }
    );



    // helper functions
    function prettyLog(str) {
        console.log("---------------------------\n" + str);
        if (CONFIG.printStackTrace === true) {
            printStackTrace();
        }
    }

    function prettyPrint(path, buffer) {
        if (CONFIG.printEnable === false) return "";

        if (contains(path, CONFIG.dump_ascii_If_Path_contains)) {
            return b2s(buffer);
        } else if (!contains(path, CONFIG.dump_hex_If_Path_NOT_contains)) {
            return hexdump(b2s(buffer));
        }
        return "[dump skipped by config]";
    }

    function rawPrint(path, buffer) {
        if (CONFIG.printEnable === false) return "";

        if (!contains(path, CONFIG.dump_raw_If_Path_NOT_contains)) {
            return hexdump(buffer);
        }
        return "[dump skipped by config]";
    }

    function contains(path, patterns) {
        for (var i = 0; i < patterns.length; i++)
            if (path.indexOf(patterns[i]) > -1) return true;
        return false;
    }

    function printStackTrace() {
        var th = Java.cast(CLS.Thread.currentThread(), CLS.Thread);
        var stack = th.getStackTrace(),
            e = null;

        for (var i = 0; i < stack.length; i++) {
            console.log("\t" + stack[i].getClassName() + "." + stack[i].getMethodName() + "(" + stack[i].getFileName() + ")");
        }
    }

    function isZero(block) {
        var m = /^[0\s]+$/.exec(block);
        return m != null && m.length > 0 && (m[0] == block);
    }

    function hexdump(buffer, blockSize) {
        blockSize = blockSize || 16;
        var lines = [];
        var hex = "0123456789ABCDEF";
        var prevZero = false,
            ctrZero = 0;
        for (var b = 0; b < buffer.length; b += blockSize) {
            var block = buffer.slice(b, Math.min(b + blockSize, buffer.length));
            var addr = ("0000" + b.toString(16)).slice(-4);
            var codes = block.split('').map(function(ch) {
                var code = ch.charCodeAt(0);
                return " " + hex[(0xF0 & code) >> 4] + hex[0x0F & code];
            }).join("");
            codes += "   ".repeat(blockSize - block.length);
            var chars = block.replace(/[\\x00-\\x1F\\x20\n]/g, '.');
            chars += " ".repeat(blockSize - block.length);
            if (isZero(codes)) {
                ctrZero += blockSize;
                prevZero = true;
            } else {
                if (prevZero) {
                    lines.push("\t [" + ctrZero + "] bytes of zeroes");
                }
                lines.push(addr + " " + codes + "  " + chars);
                prevZero = false;
                ctrZero = 0;
            }
        }
        if (prevZero) {
            lines.push("\t [" + ctrZero + "] bytes of zeroes");
        }
        return lines.join("\\n");
    }

    function b2s(array) {
        var result = "";
        for (var i = 0; i < array.length; i++) {
            result += String.fromCharCode(modulus(array[i], 256));
        }
        return result;
    }

    function modulus(x, n) {
        return ((x % n) + n) % n;
    }

});
```
