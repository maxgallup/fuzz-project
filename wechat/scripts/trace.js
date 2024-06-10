Java.perform(function() {
    var Runtime = Java.use("java.lang.Runtime");
	var arr = new Array();
	var traceLibs = [
		"libmmimgcodec.so",
		"libemojihelper.so",
		"libwechatWordDetectMod.so",
		"libwechatQrMod.so",
		"libaudio_common.so",
		"libcodec_factory.so",
		"libqqmusic_decoder_jni.so",
		"libxlabeffect.so"
	];
	
	console.log("");
	
	function traceLibrary(libName) {
		var libFullName = "lib" + libName + ".so";

		if (arr.indexOf(libName) == -1 && traceLibs.indexOf(libFullName) != -1) {
			console.log("Tracing " + libFullName);
			
			var module = Process.getModuleByName(libFullName);
			for (var exp of module.enumerateExports()) {
				if (exp.type == "function") {
					try {
						Interceptor.attach(exp.address, {
							onEnter(args) {
								console.log(libFullName + "!" + exp.name);
							}
						});
					}
					catch (e) { };
				}
			}
			
			arr.push(libName);
		}
	}
	
	Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(classObj, libName) {
		var ret = this.loadLibrary0(classObj, libName);
		traceLibrary(libName);
		return ret;
	}

	Runtime.loadLibrary0.overload('java.lang.ClassLoader', 'java.lang.String').implementation = function(classLoader, libName) {
		var ret = this.loadLibrary0(classLoader, libName);
		traceLibrary(libName);
		return ret;
	}

	Runtime.loadLibrary0.overload('java.lang.ClassLoader', 'java.lang.Class', 'java.lang.String').implementation = function(classLoader, classObj, libName) {
		var ret = this.loadLibrary0(classLoader, classObj, libName);
		traceLibrary(libName);
		return ret;
	}
});
