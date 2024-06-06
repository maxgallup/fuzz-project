Java.perform(function() {
  var Runtime = Java.use("java.lang.Runtime");
var arr = new Array();

console.log("");

Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(classObj, libName) {
  if (arr.indexOf(libName) == -1) {
    console.log("Loading lib" + libName + ".so");
    arr.push(libName);
  }
  return this.loadLibrary0(classObj, libName);
}

Runtime.loadLibrary0.overload('java.lang.ClassLoader', 'java.lang.String').implementation = function(classLoader, libName) {
  if (arr.indexOf(libName) == -1) {
    console.log("Loading lib" + libName + ".so");
    arr.push(libName);
  }
  return this.loadLibrary0(classLoader, libName);
}

Runtime.loadLibrary0.overload('java.lang.ClassLoader', 'java.lang.Class', 'java.lang.String').implementation = function(classLoader, classObj, libName) {
  if (arr.indexOf(libName) == -1) {
    console.log("Loading lib" + libName + ".so");
    arr.push(libName);
  }
  return this.loadLibrary0(classLoader, classObj, libName);
}
});
