Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);


// We are attaching to an InstructionProbeCallback instead of the Invocation
// callback which has an OnEnter and OnLeave callback.
Interceptor.attach(ptr('0x00407fac'), function(args) {
    var rbp = this.context.rbp;

    var state_addr = rbp.sub(0x5c);
    var state = Memory.readS32(state_addr);
    Afl.IJON.max(0, state);
});

Afl.done();
Afl.print("done");
