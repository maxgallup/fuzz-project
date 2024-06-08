// This script will trace all methods in the package com.linecorp.andromeda
Java.perform(function () {
    // Specify the package name to trace
    var targetPackage = "com.linecorp.andromeda";

    // Find the loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            if (className.startsWith(targetPackage)) {
                try {
                    var targetClass = Java.use(className);
                    var methods = targetClass.class.getDeclaredMethods();

                    methods.forEach(function (method) {
                        var methodName = method.getName();
                        if (methodName.startsWith("n")) {
                            targetClass[methodName].overloads.forEach(function (overload) {
                                overload.implementation = function () {
                                    var logMessage = "Tracing " + className + "." + methodName + "\n";
                                    // console.log("Tracing " + className + "." + methodName);
                                    for (var i = 0; i < arguments.length; i++) {
                                        // console.log("    arg[" + i + "]: " + arguments[i]);
                                        logMessage += "    arg[" + i + "]: " + arguments[i] + "\n";
                                    }
                                    // call origin method
                                    var retval = overload.apply(this, arguments);
                                    // console.log("    return: " + retval);
                                    logMessage += "    return: " + retval + "\n";
                                    send(logMessage);
                                    return retval;
                                };
                            });
                        }
                    });
                } catch (e) {
                    console.error(e);
                }
            }
        },
        onComplete: function () {
            console.log("Tracing complete");
        }
    });
});
