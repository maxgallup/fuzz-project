# Flatpak

Similar to AppImages the flatpak includes a sandboxed environment for the application to run in. 

Flatpaks come with a "runtime" (Freedesktop, Gnome, KDE, Elementary) which includes some essential libraries.

For libraries that aren't included in chosen runtime they can be bundled, but in general it is better to use libraries from the runtime.

* Base Apps are collections of bundled dependencies which can be add as part of an application, for example Electron base app.
* Extensions to the bundles also exist

