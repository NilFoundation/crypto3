# Chia Network VDF Competition # {#chia_vdf_impl}

@tableofcontents

## Summary

For the VDF, Lehmer's algorithm for calculating the GCD has been extended to reduce a quadratic form. Also, a SIMD two's
complement implementation of integers is used and Lehmer's algorithm is parallelized to some extent to make better use
of superscalar CPU cores (it still runs on a single thread).

For calculating the order, the parallel pollard rho algorithm is used on a GPU. This is discussed at the bottom of this
file. I didn't use the better algorithms because I didn't know about them until it was too late to implement them.

Some methods for increasing the speed of both implementations are discussed.

The only dependencies are GMP. The first sample entry code is used as a fallback; it is licensed under the Apache
license. The CUDA runtime is required to build and run the GPU code.

## Lehmer's algorithm for reduction of quadratic forms

Lehmer's algorithm is used for calculating the GCD. It is described here:
https://gmplib.org/manual/Lehmer_0027s-Algorithm.html#Lehmer_0027s-Algorithm

Reduction involves repeatedly applying the following operations:

    q = floor( (c+b)/(2c) )
    a' = c
    b' = 2qc - b
    c' = q^2c - qb + a

The integers a, b, c are usually about the same size and q is usually about 5 bits. Reduction requires about 200
iterations to reduce the 2048-bit squaring outputs back to 1024 bits. The theoretical upper bound on the reduced size of
C is 2048 bits but it is usually no more than 1024 bits after the first 10 or so squarings. If reduction is not
performed after every squaring, the number of bits will grow exponentially and reduction will require more iterations in
total than if it was performed every time.

The values of a, b, and c are truncated to 64 bits. This is modelled mathematically by dividing the values by 2^n to
make them 64 bits excluding the fraction (which has no effect on the output of the algorithm). The fraction is then
replaced by an error term which is between 0 and 1.

    v = <a0,b0,b0> ; integers. these are the truncated values of the input integers
    e = <a1,b1,c1> ; 0<=a1<1. these are the error terms

The updates to a, b, and c can be represented using matrix multiplication. At each step, a 3x3 matrix is created which
multiplies <a,b,c> to create <A,B,C>. These matricies are all multiplied together to create a matrix M which operates on
the original input values and generates the current values. The values in the matrix only depend on the quotients and
are exact integers.

    <a,b,c> = M*(v+e) ; these are the exact updated values of a, b, and c
    <av,bv,cv> = M*v  ; these are the calculated values used to calculate q
    <ae,be,ce> = M*e  ; these are the error terms

    M=[Maa Mab Mac
       Mba Mbb Mbc
       Mca Mcb Mcc]

    be = Mba*a1 + Mbb*b1 + Mbc*c1
    be >= min(Mba, 0) + min(Mbb, 0) + min(Mbc, 0) ; be <= max(Mba, 0) + max(Mbb, 0) + max(Mbc, 0)
    |be|<=E ; E=3*max(|Maa|, |Mab|, |Mac|, |Mba|, |Mbb|, |Mbc|, |Mca|, |Mcb|, Mcc)
    |ae|<=E ; based on the same reasoning
    |ce|<=E

A value of q is guessed based on the current approximate values of a, b, and c. The guessed value of q is correct if and
only if its exact remainder is between 0 and the exact denominator. The guessed value of q is also used to create
approximate values of a', b', and c'.

    m = b+c-2cq, m >= 0, m < 2c                                 ; m is the remainder of the division
    m = b+c-2cq = b+c(1-2q)
    m/c = (b+c(1-2q))/c = b/c + (1-2q) ; 0<=m/c<2

    -(1-2q) <= b/c < 2-(1-2q)
    -1+2q <= b/c < 1+2q

    -1 <= b/c - 2q < 1
    -c <= b - 2qc < c                                           ; this is the exact condition

    -c <= b - 2qc:
    -c+E <= b - E - 2q(c-E) ; -c-E <= b - E - 2q(c+E)           ; if this is true then the first part of the exact
    0 <= b - E - 2q(c-E) + c - E ; 0 <= b - E - 2q(c+E) + c + E ; condition is true
    0 <= b + c - 2qc - 2E + 2qE ; 0 <= b + c - 2qc - 2qE
    0 <= b + (1 - 2q)c - (2 - 2q)E ; 0 <= b + (1 - 2q)c - 2qE
    (2 - 2q)E <= b + (1 - 2q)c ; 2qE <= b + (1 - 2q)c

    q=0:
    2E <= b+c ; 0 <= b+c
    c-b' = b+c - 2qc = b+c

    q>=1 ; b>=c:
    2qE <= b + (1 - 2q)c = c-b'

    q<=-1 ; b<-c:
    (2-2q)E <= c-b'

    condition approximately the same as: 2(|q|+1)E <= c-b' = a'-b'

    b - 2qc < c                                                    ; this is the other part of the exact condition
    b+E - 2q(c-E) < c-E ; b+E - 2q(c+E) < c+E
    b+E - 2qc + 2qE < c-E ; b+E - 2qc - 2qE < c+E
    b + E - 2qc + 2qE - c + E < 0 ; b + E - 2qc - 2qE - c - E < 0
    E + E + 2qE + b - 2qc  - c < 0 ; E - E - 2qE - 2qc + b - c < 0
    (2 + 2q)E + b - (2q+1)c < 0 ; - 2qE + b - (2q+1)c < 0
    (2 + 2q)E < (2q+1)c - b ; -2qE < (2q+1)c - b
    (2 + 2q)E < 2qc - b + c ; -2qE < 2qc - b + c
    (2 + 2q)E < b' + c ; -2qE < b' + c

    q=0:
    2E < b' + c ; 0 < b' + c

    q>=1 ; b>=c:
    (2 + 2q)E < b' + c
    2(1 + |q|)E < c + b'

    q<=-1 ; b<-c:
    -2qE < c + b'
    2|q|E < c + b'
    2|q|E <= 2(1 + |q|)E

    final condition:
    2(|q|+1)E < a'-|b'|

If the quotient meets this condition, it is correct. The current matrix is multiplied on the left by the following
matrix:
[0  0   1 0 -1  2q 1 -q q^2]

If the quotient does not meet the condition, the algorithm terminates. For a 64-bit implementation this will happen
after about 32 bits.

Additionally, the number of bits in each matrix value must not be too high.

The algorithm also needs to terminate if a or c become negative or 0. This does not necessarily mean that reduction has
finished.

Once the algorithm has terminated, the matrix is applied to the exact values of a, b, and c to yield new values with
less bits, and the algorithm is applied to the new values.

If the algorithm terminates and returns the identity matrix, meaning that no quotients were applied, then either the
quadratic form is reduced or there is a large quotient and one step of the basic algorithm needs to be applied before
using Lehmer's algorithm again.

The divisions for this and GCD are implemented using a table. The top 12 bits of the denominator are selected (usually
the highest bit is a 1) and used as the index for a lookup table to get the fixed point inverse. The fixed point inverse
is calculated at startup by dividing 2^128-1 by the input value and taking the top 64 bits. The fixed point inverse is
multiplied by the numerator and the top 64 bits are taken (the numerator may be negative in two's compliment).

Since the denominator was right shifted to take the 12 highest bits, the result also needs to be arithmetic right
shifted by the same amount.

The remainder is then calculated and the result is known to be correct

The hit rate of this table is about 99% for GCD and reduce and it takes up about half the L1 cache since only half of it
is used most of the time (because the top bit of the index is 1 usually).

It is possible to parallelize the GCD and reduce algorithms by having a master core that runs two levels of Lehmer's
algorithm and sends the matricies to slave cores as they are generated. The slave cores spin until there are new
matricies and calculate some of the multiplications. When the master core is not able too generate any new matricies, it
gets the multiplication results from the slave cores except some of the matricies have not been applied yet; this
prevents the 100-cycle inter-core latency from blocking the master core. The master core will apply the unapplied
matricies to the truncated integers and continue generating new matricies. No OS syncronization primitives should be
used because everything is supposed to run on separate physical cores. The cache lines must be managed carefully to
avoid false sharing; prefetching might be required also to prevent the master core from blocking. The thread affinity
and priority might need to be assigned. This wasn't implemented.

This algorithm is implemented in simd_integer_reduce.h and simd_integer_reduce_asm.h.

## SIMD integers

There is a custom integer implementation. Due to time constraints it is only used for GCD and reduce. It has a 2x
speedup on Skylake client core over the fastest possible scalar implementation for 1024-bit integer multiplication but
this is not achieved because the code is not optimized fully. It would be faster with AVX-512 instructions but they are
not supported by the Skylake client core. The main performance limitation is that the AVX2 instructions only support 32
bit multiplication. There are some AVX-512 instructions that support larger integer multiplications and it is also
possible to extract the low part of the double multiplication by repeating the multiplication with an FMA and
subtracting the high part. This was not done.

The carry logic is a significant bottleneck for GCD and reduce but there are ways to optimize it.

The integers are stored in little endian limb order and are two's compliment. The lower 29 bits of each integer are for
data and the high 35 bits are for carry. This encoding is used because AVX2 has a 32-bit integer multiplication
instruction with a 64-bit output.

To perform a carry, the 35 carry bits of any limb are sign-extended to 64 bits and added to the next highest limb. The
35 bits are then zeroed out. This can be done in any order. It is possible to do 31 single-limb multiply-adds or
multiply-subtracts before having to do a carry round. As long as each limb is carried at least once in any order, this
will allow an additional 31 operations. Additions and subtractions can be mixed. Signed overflow must never be allowed
to happen, and it won't happen as long as the limit of 31 operations is respected. Carrying is done once all of the
carry bits are 0.

To perform a single-limb multiply-add, the input to be multiplied is multiplied by the single limb using SIMD 32-bit
multiplication and the 64-bit result is added to the output. The input being multiplied must be fully carried which
causes performance bottlenecks for GCD and reduce.

The SIMD carry algorithm will calculate all of the carries starting from the most significant limb. This allows all of
the carry calculations to be parallelized. It usually converges in two rounds if the inputs are random. The main
exception is a zero-padded input which changes sign, which will result in a quadratic time worst-case. Another exception
is certain patterns that can propagate in zero padding even if there is no sign change (e.g. a lower limb of all 1s and
an upper limb with only the least significant bit set). These can be dealt with by adding something to each limb, doing
one carry round, subtracting what was added, then doing the rest of the carry rounds. The SIMD carry algorithm has some
performance issues on Skylake and can only run at about 2 IPC. Skylake does not like it if both the ALUs and L1 cache
are being operated at full throughput even if the 4 IPC limit is respected.

For efficient integer multiplication on Skylake, it is necessary to use 5 accumulator registers and calculate the
products of 3 inputs from each integer at once and add the 9 results to the 5 accumulators. This hasn't been
implemented.

Integer matrix multiplication can be sped up by calculating the results without writing intermediate results to the L1
cache.

Division uses the algorithm described in this book:
https://members.loria.fr/PZimmermann/mca/pub226.html

The top two limbs of the denominator are used to calculate the fixed point inverse as described above. However, doubles
are used instead of integers. This is made more efficient because the top bit of the denominator must be set since it is
required to be normalized. The lower limb is truncated to make it fit in a double. The result of the fixed point
multiplication must be greater than or equal to the actual quotient limb. Only two limbs of the numerator are used to
calculate the quotient limb. Usually the guessed quotient limb will be correct. If not, it will make the numerator
negative when the scaled denominator is subtracted from the numerator, and the quotient limb will be adjusted. This
isn't actually used except in the GPU code.

The non-assembly SIMD integer implementation is in the simd_integer_* files that don't end with "asm". It is only used
for testing the assembly code. simd_integer_test.cpp has some test code for manual testing.

## Assembly code

Currently, the assembly code is only used to calculate the GCD and reduction due to development time constraints. There
is a division implementation but it hasn't been compiled. There are also integer multiplication implementations but they
are not optimized as well as they could be.

In hindsight it would have been better to use a JIT compiler that can also simulate the code instead of compiling it.
During simulation, each outputted ASM instruction is immediately simulated instead, and instructions can be outputted
repeatedly or out of order. If the instruction is a branch, the next instruction must be the label for the branch
target. This is not implemented and an ahead of time compiler is used which results in a clunky interface.

The assembly code is generated by C++ code. Each C++ function can allocate registers, call other functions, and create
macros for the assembly code that are local to the C++ function.

For example, the logical_shift_right function contains these lines:

This creates a new scope for macro substitution. The scope ends when the function returns:
EXPAND_MACROS_SCOPE;

This creates a macro for an input register to the function:
m.bind(bits, "bits");

This allocates a register and creates a macro for it:
reg_vector this_data=regs.bind_vector(m, "this_data");

This assigns an immediate and can allocate space in a constant table:
asm_immediate.assign(data_mask_reg, data_mask);

This appends an instruction the ASM code buffer. It also substitutes the macros:
APPEND_M(str( "VPSUBQ `data_size_minus_bits, `data_size_minus_bits, `bits" ));

This calls a function to create a memory address string for a memory instruction, and inserts the string into an
instruction:
APPEND_M(str( "VMOVDQU `next_data, #", (*this)[index+1] ));

The assembly code output contains a label for each line so that the debugger can be used. It also contains the line
number and function name for the C++ code, along with the line before preprocessing. It would probably be better to just
put the C++ filename and line number in the assembly label. It is possible to use a debugger to debug the assembly code
but it is somewhat tedious.

If the assembly code encounters an error or a rare edge case, it will return failure and the C++ code will use an
alternative implementation. This is very rare and has no effect on performance.

For the GCD and reduce algorithms, the integers must be fully carried to do a matrix multiplication. To deal with this,
the integers are split into a head and a tail region. The matricies are applied immediately to the head but they are
batched into a group of 4 matricies that are multiplied together before being applied to the tail. Also, the tail
multiplications are interleaved with the GCD/reduce algorithms so that the processor is able to issue more instructions
per cycle. The division table takes 20 cycles per iteration but it issues less than 80 instructions, so any other
instructions that are issued during that time will run concurrently with the division until a CPU throughput limit is
reached.

If there is a SIMD integer where only the highest limbs are known and the lower limbs are unknown, then carry
propagation from the lower limbs might invalidate the known limbs. However, this is guaranteed not to happen as long as
the lowest 2 known limbs are within a certain range where no carry from the highest unknown limb can change the value
above the 2nd lowest known limb. In this case, the 2 lowest known limbs are ignored and the values of the highest known
limbs are known to be valid. The known limbs must be fully carried.

The size of the head is too large so this algorithm doesn't work very well. It should probably use multiple cores as
described earlier. The algorithm is overly complicated and the multi-core version would also be simpler. The GCD
algorithm can be modified to get about a 2x speedup by interleaving the integers so that each SIMD lane has one limb
from each integer (a, b, two cofactors). Scalar carrying can then be used and the head size can be shrunk to a couple of
limbs. Also, matrix batching should be disabled since there ought to be enough throughput available in the GCD
calculations to do a LSB scalar carry concurrently with the multiplications. For reduce there is not enough throughput
available since it runs at 5 bits per iteration instead of 1.8 bits, so the multicore implementation also should be
used.

## Optimizations of other VDF code

The code in vdf_new.h is only used for testing because it is slower.

The following optimizations are used:
For normalize and reduce, it is possible to reduce the number of operations if the remainder is used in addition to the
quotient.

The following equations are used:

    s=(c+b)/(2c) ; m is the remainder so 2cs+m=c+b
    a' = c
    b' = c - m
    c' = ((b' - b - m)*s)/2 + a

These expand to the original equations.

For normalization, the quotient was observed to be 0 80% of the time and 1 20% of the time; no other values were
observed. These values are optimized for so that no division is required.

For squaring, the GCD is always 1 because it is between a and b. The GCD is still required to calculate the cofactor.
The division is exact; there is a proof in vdf.cpp. It is also possible to avoid the division in the squaring function
if the other cofactor is calculated.

If the code has a bug in it, then the discriminant will probably change (the main exception is if the sign of b is wrong
but everything else is right). To detect this, the discriminant is calculated periodically and the current state is
snapshotted. If the discriminant later becomes wrong, the state is rolled back to the last snapshot and the sample entry
code is used until the next checkpoint to skip over that state that triggers the bug. The assembly code is used from
then on so the performance overheads of both checking for bugs and recovering from them is negligible. No rollbacks were
observed during testing. This is also useful if overclocking is being done since it does not have to be 100% stable.

## GPU integers

The GPU implementation was run on a Pascal NVIDIA GPU. It would run faster on a Volta due to performance issues caused
by the compiler and the 32 bit multipliers on Volta (Pascal is 16 bits). It uses some double instructions but not enough
to cause throughput issues; I'm not sure what the latency is though. There are performance issues caused by carrying
introducing large dependency chains; this is less of a problem on Volta.

The code uses templates and loop unrolling to make all of the integers fit into registers. It does not use Lehmer's
algorithm or assembly code due to development time constraints. It does use the double-based division inverse; the cuda
integer division implementation looks like it uses Newton's method which is probably faster.

Since all of the integers are fixed size, there need to be bounds on the sizes of all intermediate results. These were
determined experimentally; there is probably some way to prove them but it didn't matter.

This runs at 25 million classgroup multiplications per second on a 1080 TI at 1.9 GHz with 170 bit discriminants (64
registers per thread). This makes the baby step algorithm require too much storage and I/O. A single Sandy Bridge core
at 3GHz runs at 50 thousand multiplications per second of the same size so the speedup is 500x over a single-core CPU
based implementation. The speedup would be higher if the GPU code were optimized better, used Lehmer's algorithm, were
written by hand in SASS using 3rd party tools, ran on a 2080 TI, etc.

## Parallel pollard rho algorithm

The method used is similar to this paper:
https://www.researchgate.net/publication/249012586_Parallelized_Pollard's_Rho_algorithm_for_ECDLP_on_Graphic_Cards

The order is unknown which affects the implementation of the algorithm. The standard version of the algorithm can't be
used because the sizes of the exponents will increase by 1 bit per iteration.

The implementation used uses only additions to the exponent. It uses a table and will randomly pick a value from the
table to add. The table has one entry per exponent bit. This limits the growth of the exponent to the log of the number
of iterations which is manageable. There must be at least as many bits in the table as the order.

In hindsight it would have been better to use the original pollard rho algorithm because multiplication by a=2, b=1 is
faster than arbitary multiplication with the right optimizations, and squaring is faster than multiplication. To deal
with the large exponent sizes, when the exponent has too many bits its hash is taken with any hashing or checksum
algorithm and the exponent is replaced with its hash. The hash should have at least as many bits as the order. The
hashing should be done at e.g. 10,000 bits. Since the resulting values will be large, two collisions should be generated
and the GCD of them taken to get a small exponent that still works. Each collision value is the order times some random
integer and the GCD of two random integers is likely to be 1 (it is small if not).

If the minimum order is required to be calculated, the GCD approach described above will work. If two collisions do not
yield the minimum order, the resulting exponent can be factored and divided by each factor to see if the divided result
still works or not. If no factors are found below a certain cutoff then the result can be assumed to be the minimum
order since the GCD of two random values is likely to be small. It is also possible to find 3 collisions and take the
GCD of them, etc. To calculate the classgroup order, the order of various random elements can be calculated and the LCM
of the results taken. The current guess for the order (initially 1) can also be applied to the random elements as an
exponent to speed up convergence. For example, if the classgroup order is known except it is missing a factor of 2, then
raising a random element to the guessed order will produce an element with an order of 1 or 2 because of Lagrange's
theorem.

The classgroup order has about the same number of bits as the discriminant because a and b each have half as many bits
as the discriminant. The subgroup order usually has about half as many bits as the subgroup order because of the
birthday paradox. If increasing the exponent by 1 randomizes the value, then a collision is likely to happen if the
exponent is around the square root of the classgroup order.

Since the pollard rho algorithm uses the birthday paradox, the probability of a result having a collision increases
linearly over time, so the runtime doesn't have very much variance.

For the parallel pollard rho algorithm, each thread is initialized with a random exponent and an iteration function is
applied to each thread's state to create the next state. The iteration function uses the quadratic form bits of the
current state as a random number generator to decide which bit to add to. It will then add to the exponent and multiply
the classgroup by the table value. This will randomize the next state so the birthday paradox time will be achieved. The
number of threads is 28,000 for the GPU implementation. It is possible to dynamically add and remove threads but this
wasn't implemented.

Once a collision has occured, the current state of one thread will be equal to the previous state of another thread.
Since only the current state is used for the next state, this means that each subsequent state will also be a collision.

A state is distinguished if enough of the random bits are all 0s. Only distinguished states need to be stored. If a
collision happens, then since each subsequent state will also be a collision, eventually there will be a collision where
the state is a distinguished state. Also, the two threads involved in the collision need to both have at least one
distinguished state before the collision happened (which is likely to be true).

Once a collision has happened, each of the two threads involved has a starting distinguished state and an end
distinguished state. The end state is the same and the starting states are different. All of the intermediate states are
regenerated on the CPU and stored in memory; there must be a collision involving these states where the exponents are
different but the reduced quadratic form values are the same. The main constraint for the number of distinguished bits
is the time and memory required to regenerate all of the intermediate states. The number of distinguished bits is set to
20 (1 in 1 million) for this implementation.

The result of collision processing is two different exponents such that `g^a = g^b` where `g` is the element whose order
is being calculated. The two exponents are subtracted to get a multiple of the order (the negation also works). It does
not matter which multiple is used. Because quadratic form multiplication is invertible, a valid exponent is guaranteed
to exist and all of the valid exponents are the order multiplied by any integer.

The implementation will create a checkpoint every 10 minutes. This saves all of its state to a file to disk. It also
validates all of the GPU state by recalculating the quadratic form values based on the exponent. If the GPU code has a
bug or there is a hardware malfunction then it is very likely that the exponent will not match the quadratic form value.
The implementation can reload from the last checkpoint after making code modifications.