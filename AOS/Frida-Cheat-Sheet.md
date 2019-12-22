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
Java.use('java.lang.reflect.Method').invoke.overload('java.lang.Object', '[Ljava.lang.Object;', 'boolean').implementation = function(a,b,c) {
    console.log('hooked!', a, b, c);
    return this.invoke(a,b,c);
};
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
