Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

Interceptor.attach(ptr('0x004024ac'), function(args) {
    var edx = this.context.rdx & 0xffffffff;
    var esi = this.context.rsi & 0xffffffff;
    var ecx = this.context.rcx & 0xffffffff;
    Afl.print(`esi: ${esi}, edx: ${edx}, ecx: ${ecx}`);
    Afl.IJON.max(0, esi);
    Afl.IJON.max(1, edx);
    Afl.IJON.max(2, ecx);
});

Afl.done();
Afl.print("done");
