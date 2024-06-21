# Background
* state fuzzing is needed because concolic execution is not powerful enough



# Abstract
Current state of the art coverage based fuzzers struggle to explore vulnerabilities linked to a program's internal state. Since they don't track program states, they have no way to mutate the input in a way that favors state exploration. Recent work in stateful fuzzing has shown that hooking into the program's in-memory state representation guides the fuzzer to target the program states and their transitions, ultimately leading to discovering previously undiscovered vulnerabilities. Since this previous work has hinged on the fact that source code is available for the hooking process, this project builds on top of that research by performing stateful fuzzing for binary only targets.





# Program State Fuzzing without source
* We use information from fuzzing a program to help us find the state variable and state enumeration
* Then we can apply SGFuzz / IJON


Existing research shows that it is possible to fuzz a program's state through manual augmentations 
(IJON) or through automated runtime analysis (SGFuzz). However, since both approaches require source
code, we would like to explore how stateful fuzzing can be acheived without source code to fuzz
binaries for different architectures. For this, we have the following steps:

1. manual identification of states and the state variable assignments through reverse engineering
2. implement the approach of IJON or SGFuzz for binary targets (this involves writing our own fuzzer)

Our end goal is to apply state-of-the art stateful fuzzing techniques to closed source binaries.


### Related Work: IJON & SGFuzz
* IJON instruments manually
* focus on visiting unobserved states




