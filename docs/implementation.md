# Implementation

Because of encoding is an accumulative algorithm, the implementation supposes a dual-usage way scheme.

1. **Single pass algorithm**. Supposes once-per data encoding with implicit accumulator state allocation. Implemented
 with ```encode``` and ```decode``` algorithms in ```codec/algorithm.hpp```

2. **Accumulator**. Supposes the initialization of container, which accumulates the data 