// Afl.print('******************');
// Afl.print('* AFL FRIDA MODE *');
// Afl.print('******************');
// Afl.print('');
// 
// Afl.print(`PID: ${Process.id}`);
// 
// const main = DebugSymbol.fromName('main').address;
// Afl.print(`main: ${main}`);
// 
// var states = [];
// var node_types = [];
// var node_names = [];


// Interceptor.attach(ptr('0x401A4A'), function(args) {
//     var edx = this.context.rdx & 0xffffffff;
//     Afl.print(`edx: ${edx}`);
//     transitions.push(edx);
//     if (transitions.length > 4) {
//         let val = 0;
//         for (let i = 0; i < 5; i++) {
//             val = Afl.IJON.hashint(val, transitions[i]);
//         }
//         Afl.print(`transitions: ${transitions}, val: ${val}`);
//         Afl.IJON.map_set(this.context, val);
//     }
// });

Interceptor.attach(ptr('0x407FAD'), function(args) {
    var rbp = this.context.rbp;
    var node_name_addr = Memory.readU64(rbp.sub(0x38));
    var state_addr = rbp.sub(0x54);
    var node_name = ptr(node_name_addr).readUtf8String();
    var state = Memory.readS32(state_addr);
    Afl.print(`node_name_addr: ${node_name_addr}, node_name: ${node_name} | state_addr: ${state_addr}, state: ${state}`);
    // console.log(`node_name_addr: ${node_name_addr}, node_name: ${node_name} | state_addr: ${state_addr}, state: ${state}`);
});

Afl.done();
Afl.print("done");

