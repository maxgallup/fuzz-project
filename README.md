# Background
* state fuzzing is needed because concolic execution is not powerful enough


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




