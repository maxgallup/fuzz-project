Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

var transitions = [];

Interceptor.attach(ptr('0x401A4A'), function(args) {
    var edx = this.context.rdx & 0xffffffff;
    Afl.print(`edx: ${edx}`);
    transitions.push(edx);
    if (transitions.length > 4) {
        let val = 0;
        for (let i = 0; i < 5; i++) {
            val = Afl.IJON.hashint(val, transitions[i]);
        }
        Afl.print(`transitions: ${transitions}, val: ${val}`);
        Afl.IJON.map_set(this.context, val);
    }
});

Afl.done();
Afl.print("done");

