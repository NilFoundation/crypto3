# Manual # {#zk_manual}

@tableofcontents

## Proving knowledge of a hashed message 

Before you start proving knowledge of a hashed message you need to construct a sha2-256 
circuit on protoboard.

We will show the process for some pairing-friendly curve `curve_type` and its scalar field `field_type`.

### Usage of SHA2-256 component

To add SHA2-256 component to `blueprint`, we need:
* generate r1cs constraints on `blueprint`;
* transform input into bit vectors;
* generate r1cs witness.

Firstly, we need to 

```
blueprint<field_type> bp;

digest_variable<field_type> left(bp, hashes::sha2<256>::digest_bits);
digest_variable<field_type> right(bp, hashes::sha2<256>::digest_bits);
digest_variable<field_type> output(bp, hashes::sha2<256>::digest_bits);

sha256_two_to_one_hash_component<field_type> f(bp, left, right, output);

f.generate_r1cs_constraints();
```

After generation of r1cs constraints we need to transform data blocks into bit vectors. 
At the moment we use custom `pack`, which allows us to convert data from arbitrary data 
type to bit vectors. The following code can be used for this purpose:

```
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

After getting bit vectors, we can generate r1cs witness:

```
left.generate_r1cs_witness(left_bv);

right.generate_r1cs_witness(right_bv);

f.generate_r1cs_witness();
output.generate_r1cs_witness(hash_bv);
```

Now we have `blueprint` with SHA2-256 component on it and can prove our knowledge of 
the source message using GROTH-16 (`r1cs_gg_ppzksnark`).

### Creating R1CS

We will use a R1CS example, which comprises a R1CS constraint system, R1CS input, and R1CS witness.

```
template<typename FieldType>
struct r1cs_example {
    r1cs_constraint_system<FieldType> constraint_system;
    r1cs_primary_input<FieldType> primary_input;
    r1cs_auxiliary_input<FieldType> auxiliary_input;

    r1cs_example<FieldType>() = default;
    r1cs_example<FieldType>(const r1cs_example<FieldType> &other) = default;
    r1cs_example<FieldType>(const r1cs_constraint_system<FieldType> &constraint_system,
                            const r1cs_primary_input<FieldType> &primary_input,
                            const r1cs_auxiliary_input<FieldType> &auxiliary_input) :
        constraint_system(constraint_system),
        primary_input(primary_input), 
        auxiliary_input(auxiliary_input) {};
    r1cs_example<FieldType>(r1cs_constraint_system<FieldType> &&constraint_system,
                            r1cs_primary_input<FieldType> &&primary_input,
                            r1cs_auxiliary_input<FieldType> &&auxiliary_input) :
        constraint_system(std::move(constraint_system)),
        primary_input(std::move(primary_input)), 
        auxiliary_input(std::move(auxiliary_input)) {};
};
```

Creation of `r1cs_example` from `blueprint` can be done as follows:

```
r1cs_example<field_type> r1cs = r1cs_example<field_type>(bp.get_constraint_system(), 
    														bp.primary_input(), 
    														bp.auxiliary_input());
```

Where `bp` is `blueprint`, obtained previously.

### Proving the knowledge

Using obtained `r1cs_example` we can finally create and verify `proof`:

```
using grth16 = r1cs_gg_ppzksnark<curve_type>;

typename grth16::keypair_type keypair =
    grth16::generator(r1cs.constraint_system);

typename grth16::proof_type proof =
    grth16::prover(keypair.pk, r1cs.primary_input, r1cs.auxiliary_input);

const bool ans = grth16::verifier(keypair.vk, r1cs.primary_input, proof);
```
