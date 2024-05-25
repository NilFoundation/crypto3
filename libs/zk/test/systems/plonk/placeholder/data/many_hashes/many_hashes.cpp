#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

[[circuit]] typename hashes::sha2<256>::block_type poseidon_example1(
    typename pallas::base_field_type::value_type b,
    typename pallas::base_field_type::value_type c,
    typename hashes::sha2<256>::block_type d,
    typename hashes::sha2<256>::block_type e,
    __zkllvm_field_curve25519_base f,
    __zkllvm_field_curve25519_base g
) {
    typename pallas::base_field_type::value_type poseidon_result = hash<hashes::poseidon>(b, c);
    typename pallas::base_field_type::value_type poseidon_result2 = hash<hashes::poseidon>(c, b);
    typename pallas::base_field_type::value_type poseidon_tmp;

    typename hashes::sha2<256>::block_type sha2_result = hash<hashes::sha2<256>>(d, e);
    typename hashes::sha2<256>::block_type sha2_result2 = hash<hashes::sha2<256>>(e, d);
    typename hashes::sha2<256>::block_type sha2_tmp;

    __zkllvm_field_curve25519_base curve_add;
    __zkllvm_field_curve25519_base curve_mul;
    __zkllvm_field_curve25519_base curve_sub;

    // We can not commit the assignment table for larger rounds.
    // This number can be changed to manually run larger performance tests.
    int rounds = 3;

    for( int i = 0; i < rounds; i++ ) {
        curve_add = f+g;
        curve_sub = f-g;
        curve_mul = f*g;

        f = curve_add;
        g = curve_sub;

        poseidon_tmp = hash<hashes::poseidon>(poseidon_result, poseidon_result2);
        poseidon_result = poseidon_result2;
        poseidon_result2 = poseidon_tmp;

        sha2_tmp = hash<hashes::sha2<256>>(sha2_result, sha2_result2);
        sha2_result = sha2_result2;
        sha2_result2 = sha2_tmp;
    }

    return sha2_result2;
}

