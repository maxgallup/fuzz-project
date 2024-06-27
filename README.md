# Stateful Fuzzing with Runtime Instrumentation


### Background
Some programs tend to use some kind of internal state to manage the behaviour of the program itself.
For example, file parsers or protocol implementations tend to have a rather complex finite state
machine (FSM). Stateful fuzzing aims to target this implementation of the state machine itself by
hooking into the program and reading the state variables. For example in the code below, a hook was
annotated into the source code which calls into the fuzzing process with the value of the state
variable, effectively allowing the fuzzer to mutate the input to target things like _new states_
_or new state transitions._

```c
// ...
enum MyState state = MY_BEGIN;

while(state != MY_TERMINATE) {
    fuzzer_hook(state);
    switch(state) {
        case MY_BEGIN:
        // ...
        // complex state logic
        //
    }
}
```

When having the target's source code available, one can add annotations like `fuzzer_hook(state)`
that enable the fuzzer to more informed decisions about which inputs are preferred for advanccing
the fuzzing of the state. Exisiting research such as
[_IJON: Exploring Deep State Spaces via Fuzzing_](https://ieeexplore.ieee.org/document/9152719/)
does exactly this and also provides a set of primitives on how the fuzzer should process the added
state information.


### This Project
This project builds directly on top of the work done by IJON and tries to answer the question
whether it is possible to implement stateful fuzzing **without** having the source code available.

The code found in this repository is an accumulation of research done for this project and mainly
contains all the evaluation data & results. The comparisons were made largely between the existing
(original) IJON implementation, our adapted IJON implementation that uses Frida. Some evaluations
were also made on a real world example namely, [svg2ass](https://github.com/irrwahn/svg2ass).

The directories starting with `eval-` contain all data and necessary test scripts for their
respective evaluations. The `plots` directory contains all plots used in the presentation as well as
the paper.


### Reproducability
Each `eval-` directory contains a `test.py` script that runs multiple fuzzing campaigns for testing,
but see the README of each directory for details. These can take a long time to complete depending
on the number of available cores, however results can be saved intermittently simply by running
`save-results.py`. After results have been saved, `plot.py` can be run to generate plots in `/plots`
directory. For the `eval-new-ijon` we use a
[fork of AFL++](https://github.com/meowmeowxw/AFLplusplus) where we implemented the customizations
necessary to implement stateful fuzzing with runtime instrumentation.



