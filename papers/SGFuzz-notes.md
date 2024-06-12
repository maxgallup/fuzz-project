# SGFuzz paper Notes
* stateful bugs are only revealed when the program is in a certain state
* key challenge is to cover state space without an explicit specification of the protcol
* automatically find state variable enum to produce a map of the explored state space
* constructs lightweight abstraction over state space, navigates it to **maximize probability of visiting unobserved states**
* Their instrumentation injects call  at every program location where a state var is assigned to a new value
    * (all assignments of special variable E are hooked)

### Fuzzing insights
* add generated inputs to the seed corpus that exercise new nodes in the STT (state trans. tree)
* heuristics
    1. simply reaching an unexplored new state 
    2. focus on seeds which traverse the rarely visited nodes of the STT
    3. focus on bytes that trigger new nodes in STT

###  Offline State Variable Identification
* scan source code for all variables of `enum` type (regex)
* 
