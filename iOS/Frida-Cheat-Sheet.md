## **Frida Cheat Sheet**

### **Basic Hooking**

```js
// Hook
if(ObjC.available){

	console.log();

	var baseAddress = Module.findBaseAddress('archero');

	Interceptor.attach(baseAddress.add(0x205aea4),{
		onEnter: function(args){
			console.log('[+] 0x205aea4');
			console.log('[+] args0:'+ObjC.Object(args[0]));
		},
		onLeave: function(retval){
			console.log('    [+] retval:'+retval);
		}

	})


	Interceptor.attach(ObjC.classes.NSMutableURLRequest['- setHTTPBody:'].implementation,{
		  onEnter: function (args) {

			    console.log('-[NSMutableURLRequest setHTTPBody:');
			    console.log('  args[0]:'+ObjC.Object(args[2]));
		    

		  },onLeave: function(retval){
		  	console.log('  return:'+ObjC.Object(retval));
		  }
	})
}else{
	console.log("Objective-C Runtime is not available!");
}
```

### **File Open**

```js
// File Open
var trigger=false;
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {
        console.log('open:' , ObjC.Object(args[2]).toString());
        if(ObjC.Object(args[2]).toString()=='/Applications/Cydia.app' || 
        	ObjC.Object(args[2]).toString()=='/Library/MobileSubstrate/MobileSubstrate.dylib' ||
        	ObjC.Object(args[2]).toString()=='/bin/bash' ||
        	ObjC.Object(args[2]).toString()=='/usr/sbin/sshd' ||
        	ObjC.Object(args[2]).toString()=='/etc/apt' 
        	){
        	trigger=true;
        }
    },
	onLeave: function(retval){
		console.log('retval:' + retval);
		if(trigger){
			retval.replace(ptr(0x0));
			console.error('mod ret:'+retval);
			trigger=false;
		}
	}
});
```

### **Extract Cookies**

```js
// Extract Cookies
var cookieJar = {};
var cookies = ObjC.classes.NSHTTPCookieStorage.sharedHTTPCookieStorage().cookies();
for (var i = 0, l = cookies.count(); i < l; i++) {
  var cookie = cookies['- objectAtIndex:'](i);
  cookieJar[cookie.Name()] = cookie.Value().toString(); // ["- expiresDate"]().toString()
}
console.log(JSON.stringify(cookieJar, null, 2));
```

### **Enumerate Modules**

```js
// Enumerate Modules
Process.enumerateModules({
	onMatch: function(module){
		console.log('Module name: ' + module.name + " - " + "Base Address: " + module.base.toString());
	}, 
	onComplete: function(){}
});
```

### **ObjSend Hook**

```js
// ObjSend Hook
Interceptor.attach(Module.findExportByName('/usr/lib/libobjc.A.dylib', 'objc_msgSend'), {
	onEnter: function(args) {
		var m = Memory.readCString(args[1]);
		//console.log(m);
	}
});
```

### **NSDictionary Hooking**

```js
// NSDictionary Hook
Interceptor.attach(ObjC.classes.ThinkingAnalyticsSDK['- track:properties:'].implementation,{
	  onEnter: function (args) {
	  	var receiver = ObjC.Object(args[0])
	  	console.log('-[ThinkingAnalyticsSDK track:properties:]');
	    console.log('  args[0]:'+ObjC.Object(args[2]));
	    console.log('  args[1]:'+ObjC.Object(args[3]));


	    var arg0 = ObjC.Object(args[3]);
	    
	    var enumerator = arg0.keyEnumerator();
	    var key;
		// new Dictionary
	    var ns_dict = ObjC.classes.NSMutableDictionary.alloc().init(); 

	    while((key = enumerator.nextObject())!=null){

	    	if(key=='gems'){
	    		ns_dict.setObject_forKey_(20,key);
	    		continue;
	    	}

	    	ns_dict.setObject_forKey_(arg0.objectForKey_(key),key);
	    }
	    arg0 = ns_dict;
	    console.error(arg0);
	  }
})
```

### **Memory Scan**

```js
// Memory Scan
function dumpAddr(addr, size) {
 if (addr.isNull())
  return;
 var buf = Memory.readByteArray(addr, size);
 console.log(hexdump(buf, { offset: 0, length: size, header: true, ansi: false }));
}

var ranges = Process.enumerateRanges('rw-');

for(var idx in ranges){
	//console.log('base:'+ranges[idx].base);
	//console.log('size:'+ranges[idx].size);

	Memory.scan(ptr(ranges[idx].base), ranges[idx].size, "39 34 38 34 30 30 31", { 

	  onMatch: function (address, size){ 
		  	console.log('====================MATCH=================');
		    console.log("address: " + address.toString()); 
		    console.log("address: " + address.name()); 
		    console.log("size: " + size); 
				
			dumpAddr(address, size);

			//address.writeByteArray([0x39,0x34,0x38,0x34,0x30,0x30,0x32]);
			
			//dumpAddr(address, size);

	    }, 

	    onError: function (reason){ 
	        console.log("reason: " + reason); 
	    }, 

	    onComplete: function (){ 
	    } 

	});
}
```