## What is a VDF?

A Verifiable Delay Function (VDF) is a function that requires substantial time
to evaluate (even with a polynomial number of parallel processors) but can be
very quickly verified as correct. VDFs can be used to construct randomness
beacons with multiple applications in a distributed network environment. By
introducing a time delay during evaluation, VDFs prevent malicious actors from
influencing output. The output cannot be differentiated from a random number
until the final result is computed.  See <https://eprint.iacr.org/2018/712.pdf>
for more details.