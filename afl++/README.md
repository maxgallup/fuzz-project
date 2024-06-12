# AFL++

## Changes

The changes can be look at: https://github.com/AFLplusplus/AFLplusplus/compare/stable...meowmeowxw:AFLplusplus:ijon.

I've changed the code of the frida mode to be able to instrument a binary with IJON functions.
I've created the IJON functions (Only the functions needed for IJON_SET) inside instrument.c:

```
uint64_t ijon_simple_hash(uint64_t x) {}
void ijon_map_set(uint32_t addr) {}
uint32_t ijon_hashint(uint32_t old, uint32_t val) {}
```

And "exported" them inside instrument.h:

```
// ijon_simple_hash does not need to be available externally
uint32_t ijon_hashint(uint32_t old, uint32_t val);
void ijon_map_set(uint32_t addr);
```

Additionally, inside `frida_mode/src/js` I've added the javascript implementations
that will call the native functions `ijon_*`.

```js
// js code
Afl.jsApiIjonMapSet = Afl.jsApiGetFunction("js_api_ijon_map_set", "void", ["uint32"]);
Afl.jsApiIjonHashint = Afl.jsApiGetFunction("js_api_ijon_hashint", "uint32", ["uint32", "uint32"]);
```

```c
// c code
__attribute__((visibility("default"))) void js_api_ijon_map_set(uint32_t addr) {
  ijon_map_set(addr);
}

__attribute__((visibility("default"))) uint32_t js_api_ijon_hashint(uint32_t old, uint32_t val) {
  return ijon_hashint(old, val);
}
```

It is possible to compile just the frida_mode by running `make` inside the `frida_mode`
directory.

## Testing

When we have the source code there are some instrumentations already available: https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.instrument_list.md#2-selective-instrumentation-with-_afl_coverage-directives.

When we dont have the source code we can use frida to instrument the running process,
which can be our way to annotate the binary with the IJON functions: https://github.com/AFLplusplus/AFLplusplus/blob/stable/frida_mode/Scripting.md.

The binary we want to instrument is `small`, available in ../binaries/.

At address 0x401345 we want to insert the IJON_SET function:

```c
		ox = x;    //Save old player position
		oy = y;
```

```asm
; var int oy @ rbp-0x214
; var int ox @ rbp-0x218
; var int i @ rbp-0x21c
; var int y @ rbp-0x220
; var int x @ rbp-0x224

0x0040132d      8b85dcfdffff   mov eax, dword [x]
0x00401333      8985e8fdffff   mov dword [ox], eax
0x00401339      8b85e0fdffff   mov eax, dword [y]
0x0040133f      8985ecfdffff   mov dword [oy], eax
0x00401345      8b85e4fdffff   mov eax, dword [i]
```

I've created a file afl.js (default filename)

```js
Interceptor.attach(ptr('0x00401345'), {
    onEnter: function(args) {
        // Read the value at rbp-0x224
        var rbp = this.context.rbp;

        // Calculate the address for rbp - 0x224 and rbp - 0x220
        var addr1 = rbp.sub(0x224);
        var addr2 = rbp.sub(0x220);

        // Read the values at these addresses
        var value1 = Memory.readS32(addr1);
        var value2 = Memory.readS32(addr2);

        Afl.print(`Value at rbp-0x224: ${value1}`);
        Afl.print(`Value at rbp-0x220: ${value2}`);
        var hash = Afl.IjonHashint(value1, value2);
        Afl.print(`Hash: ${hash}`);
        Afl.IjonMapSet(hash);
    }
});
Afl.done();
```

Now it's possible to run the fuzzer with:

```
~/Projects/AFLplusplus/afl-fuzz -O -i ./small_input_dir -o ./small_output_dir -- ../binaries/small
```

If you want to test the normal afl-fuzz without the instrumentation, it's possible to
just move the afl.js file:

```
mv afl.js afl1.js
```

At the moment the IjonMapSet function does not take in consideration the current
address, because it's only called at that address. In theory we can call it with:

```js
Afl.IjonMapSet(addr ^ hash);
```

To have a behaviour more similar to the original IJON function:

```c
#define IJON_SET(x) ijon_map_set(ijon_hashstr(__LINE__,__FILE__)^(x))
```
