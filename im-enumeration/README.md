# Enumeration

## Start

I've started enumerating LINE. I've downloaded the APK from internet, and
extracted the sources+resources with:

```
apktool decode -f line-14-8-0.apk
```

I've also downloaded the app on the phone, and then extracted the APK, but
somehow the libraries are missing in the extracted APK. But I can see that they
are used in the source code, probably the apk extractor missed the bundle
configuration or something (todo for later).

With radare2/r2pipe I've automatically extracted the symbols and exports information of
these libraries.

```
python3 enumeration.py
```

The script also create/populate a sqlite database called `line.db` with data.

## Next steps

1. Dynamic analysis with frida. Play with the app inside an emulator with frida
connected, see if there is a way to check which libraries are executed when messages,
calls, audio, etc are send/received.
2. Enhance database information with additional information and euristhics:
  - Closed/Open source library.
  - Language/Compiler used.
  - Security measures in place.
  - Something else.
3. Automatic static analysis on other IM apps apks.
