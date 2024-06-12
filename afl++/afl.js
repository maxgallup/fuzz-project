Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

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
Afl.print("done");
