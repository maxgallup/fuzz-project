Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);


// We are attaching to an InstructionProbeCallback instead of the Invocation
// callback which has an OnEnter and OnLeave callback.
Interceptor.attach(ptr('0x00401291'), function(args) {
    var rbp = this.context.rbp;

    // Calculate the address for rbp - 0x224 and rbp - 0x220
    var x_addr = rbp.sub(0x4);
    var y_addr = rbp.sub(0x8);

    var x = Memory.readS32(x_addr);
    var y = Memory.readS32(y_addr);

    var hash = Afl.IJON.hashint(y, x);
    Afl.IJON.map_set(this.context, hash);
});

Afl.done();
Afl.print("done");
