Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

const pStartAddr = DebugSymbol.fromName("run").address;
Afl.setPersistentAddress(pStartAddr);
Afl.setEntryPoint(pStartAddr);

const cm = new CModule(`

    #include <string.h>
    #include <gum/gumdefs.h>

    void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
      uint32_t input_buf_len) {

      memcpy((void *)regs->rdi, input_buf, input_buf_len);
      regs->rsi = input_buf_len;

    }
    `,
    {
        memcpy: Module.getExportByName(null, 'memcpy')
    }
);

Afl.setPersistentHook(cm.afl_persistent_hook);

Interceptor.attach(ptr('0x00402583'), function(args) {
    var edx = this.context.rdx & 0xffffffff;
    Afl.print(`edx: ${edx}`);
    Afl.IJON.max(0, edx);
});

Afl.done();
Afl.print("done");
