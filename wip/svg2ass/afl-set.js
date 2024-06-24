Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

Afl.print(`PID: ${Process.id}`);
const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);
 
var states = [];
var node_types = [];
var node_names = [];


var valid_node_names = ["svg", "g", "", "line", "rect", "circle", "ellipse", "path", "polyline", "polygon"];

function stringToIntegerRepresentation(str) {
    let num = 0;
    for (let i = 0; i < Math.min(4, str.length); i++) {
        num = (num << 8) | str.charCodeAt(i);
    }
    return num & 0xffffffff;
}

Interceptor.attach(ptr('0x407FAD'), function(args) {
    var rbp = this.context.rbp;
    var node_name_addr = Memory.readU64(rbp.sub(0x38));
    var node_type_addr = rbp.sub(0x40);
    var state_addr = rbp.sub(0x54);

    var node_name = ptr(node_name_addr).readUtf8String();
    var node_type = Memory.readS32(node_type_addr);
    var state = Memory.readS32(state_addr);
    Afl.print(`state: ${state} | node_type: ${node_type} | node_name: ${node_name}`);
    states.unshift(state);
    if (valid_node_names.includes(node_name)) {
        node_names.unshift(stringToIntegerRepresentation(node_name));
        node_types.unshift(node_type);
    }
    Afl.print(`[!] node_names: ${node_names} | node_types: ${node_types} | states: ${states}`);

    var val = 0;
    var hash = 0;
    if (node_names.length >= 2) {
        for (let i = 0; i < 3; i++) {
            val += node_names[i];
            val += node_types[i];
            // Afl.print(`node_names[i]: ${node_names[i]}, node_types: ${node_types[i]}`);
            val += states[i];
        }
        Afl.print(`val: ${val}`);
        val = val & 0xffffffff;
        hash = Afl.IJON.hashint(0, val);
        Afl.print(`val: ${val}, hash: ${hash}`);
        Afl.IJON.map_set(this.context, hash);
    }
});

Afl.done();
Afl.print("done");

