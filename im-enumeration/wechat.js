Java.perform(function() {
  var Runtime = Java.use("java.lang.Runtime");
var arr = new Array();
var callCounters = {};

console.log("");

function traceLibrary(libName) {
  if (arr.indexOf(libName) == -1) {
    var libFullName = "lib" + libName + ".so";
    console.log("Loading " + libFullName);
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
