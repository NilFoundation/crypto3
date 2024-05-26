# Manual # {#zk_manual}

@tableofcontents

## Example 1: Inner-product component

Let's show how to create a simple circuit for the calculation of the public inner product of two secret vectors. In
crypto3-zk library, the blueprint is where arithmetic circuits are collected. The statement (or public values) is called
primary_input and the witness (or secret values) is called auxiliary_input. Let `bp` be a blueprint and `A` and `B` are
vectors which inner product `res` has to be calculated.

```c++
blueprint<FieldType> bp;
blueprint_variable_vector<FieldType> A;
blueprint_variable_vector<FieldType> B;
variable<FieldType> res;
```

Then we associate the variables to a blueprint by using the function `allocate()`. The variable `n` shows the size of
the vectors `A` and `B`. Note, that each use of `allocate()` increases the size of `auxiliary_input`.

```c++
res.allocate(bp);
A.allocate(bp, n);
B.allocate(bp, n);
bp.set_input_sizes(1);
```

Note, that the first allocated variable on the blueprint is a constant 1. So, the variables on the blueprint would
be `1` , `res`, `A[0]`, ..., `A[n-1]`, `B[0]`, ..., `B[n-1]`.

To specify which variables are public and which ones are private we use the function `set_input_sizes(1)`, so only `res`
value is a primary input. Thus, usually, the primary input is allocated before the auxiliary input in the program.

*Component* is a class for constructing a particular constraint system. The component's constructor allocates
intermediate variables, so the developer is responsible for allocation only primary and auxiliary variables. Any
Component has to implement two methods: `generate_r1cs_constraints()` and `generate_r1cs_witness()`.

Now we initialize the simple component `inner_product_component`. The function `generate_r1cs_constraints()` add R1CS
constraints to the blueprint corresponding to the circuit.

```c++
inner_product_component<FieldType> compute_inner_product(bp, A, B, res, "compute_inner_product");
compute_inner_product.generate_r1cs_constraints();
```

Next, we set the random values to vectors.

```c++
for (std::size_t i = 0; i < n; ++i) {
    bp.val(A[i]) = algebra::random_element<FieldType>();
    bp.val(B[i]) = algebra::random_element<FieldType>();
}
```

The function `generate_r1cs_witness()` computes intermediate witness value for the public values and the inner product
for the `res`.

```c++
compute_inner_product.generate_r1cs_witness();
```

### Proof generation

Using the example above we can finally create and verify `proof`.

* The generator `grth16::generator` creates proving keys and verification keys for our constraints system.
* The proving key `keypair.pk`, public input `bp.primary_input`, and private input `bp.auxiliary_input` are used for the
  constructing of the proof (`grth16::prover`).
* For verifying of the `proof`  we use verifying key `keypair.vk`, public input `bp.primary_input` in
  the `grth16::verifier`.

```c++
using grth16 = r1cs_gg_ppzksnark<curve_type>;
typename grth16::keypair_type keypair = grth16::generator(bp.get_constraint_system());

typename grth16::proof_type proof =
    grth16::prover(keypair.pk, bp.primary_input, bp.auxiliary_input);

const bool ans = grth16::verifier(keypair.vk, bp.primary_input, proof);
```

We expect to obtain the boolean value `ans == true`, which says that we have a correct proof.

## Example 2: SHA2-256 component

Now we want to consider a more complicated construction of a circuit. Assume that the prover wants to prove that they
know a preimage for a hash digest chosen by the verifier, without revealing what the preimage is. Let hash function be a
2-to-1 SHA256 compression function for our example.

We will show the process for some pairing-friendly curve `curve_type` and its scalar field `field_type`.

Firstly, we need to create a `blueprint` and allocate the variables `left`, `right` and `output` at the blueprint. The
allocation on the blueprint proceeds at the constructor of digest_variable. Then we initialize the
gadget ` sha256_two_to_one_hash_component ` and add constraints at the `generate_r1cs_constraints()` function.

```c++
blueprint<field_type> bp;

digest_variable<field_type> left(bp, hashes::sha2<256>::digest_bits);
digest_variable<field_type> right(bp, hashes::sha2<256>::digest_bits);
digest_variable<field_type> output(bp, hashes::sha2<256>::digest_bits);

sha256_two_to_one_hash_component<field_type> f(bp, left, right, output);

f.generate_r1cs_constraints();
```

After the generation of r1cs constraints, we need to transform data blocks into bit vectors. We use a custom `pack`,
which allows us to convert data from an arbitrary data type to bit vectors. The following code can be used for this
purpose:

```c++
std::array<std::uint32_t, 8> array_a_intermediate;
std::array<std::uint32_t, 8> array_b_intermediate;
std::array<std::uint32_t, 8> array_c_intermediate;

std::array<std::uint32_t, 8> array_a = {0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 
                                        0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9};
std::array<std::uint32_t, 8> array_b = {0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 
                                        0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0};
std::array<std::uint32_t, 8> array_c = {0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 
                                        0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1};

std::vector<bool> left_bv(hashes::sha2<256>::digest_bits), 
                  right_bv(hashes::sha2<256>::digest_bits), 
                  hash_bv(hashes::sha2<256>::digest_bits);

detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
    array_a.begin(),
    array_a.end(),
    array_a_intermediate.begin());

detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
    array_b.begin(),
    array_b.end(),
    array_b_intermediate.begin());

detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
    array_c.begin(),
    array_c.end(),
    array_c_intermediate.begin());

detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(
    array_a_intermediate,
    left_bv.begin());

detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(
    array_b_intermediate,
    right_bv.begin());

detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(
    array_c_intermediate,
    hash_bv.begin());
```

After getting bit vectors, we can generate r1cs witnesses.

```c++
left.generate_r1cs_witness(left_bv);

right.generate_r1cs_witness(right_bv);

f.generate_r1cs_witness();
output.generate_r1cs_witness(hash_bv);
```

Now we have the `blueprint` with SHA2-256 component on it and can prove our knowledge of the source message using
Groth-16 (`r1cs_gg_ppzksnark`)  as we did before .
