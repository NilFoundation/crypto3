//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_TEST_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_TEST_HPP

#include <nil/blueprint/components/hashes/sha2/r1cs/sha256_component.hpp>
#include <nil/blueprint/components/hashes/hash_io.hpp>
#include <nil/blueprint/blueprint/r1cs/circuit.hpp>
#include <nil/blueprint/blueprint/r1cs/assignment.hpp>

#include <nil/crypto3/hash/sha2.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra;
using namespace nil::crypto3::zk;

template<typename FieldType>
blueprint<FieldType> sha2_two_to_one_bp() {
    blueprint<FieldType> bp;

    components::digest_variable<FieldType> left(bp, hashes::sha2<256>::digest_bits);
    components::digest_variable<FieldType> right(bp, hashes::sha2<256>::digest_bits);
    components::digest_variable<FieldType> output(bp, hashes::sha2<256>::digest_bits);

    components::sha256_two_to_one_hash_component<FieldType> f(bp, left, right, output);

    f.generate_gates();
    std::cout << "Number of constraints for sha256_two_to_one_hash_component: " << bp.num_constraints() << std::endl;

    std::array<std::uint32_t, 8> array_a_intermediate;
    std::array<std::uint32_t, 8> array_b_intermediate;
    std::array<std::uint32_t, 8> array_c_intermediate;

    std::array<std::uint32_t, 8> array_a = {0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148,
                                            0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9};
    std::array<std::uint32_t, 8> array_b = {0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53,
                                            0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0};
    std::array<std::uint32_t, 8> array_c = {0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48,
                                            0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1};

    std::vector<bool> left_bv(hashes::sha2<256>::digest_bits), right_bv(hashes::sha2<256>::digest_bits),
        hash_bv(hashes::sha2<256>::digest_bits);

    nil::crypto3::detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
        array_a.begin(), array_a.end(), array_a_intermediate.begin());

    nil::crypto3::detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
        array_b.begin(), array_b.end(), array_b_intermediate.begin());

    nil::crypto3::detail::pack<stream_endian::big_octet_little_bit, stream_endian::little_octet_big_bit, 32, 32>(
        array_c.begin(), array_c.end(), array_c_intermediate.begin());

    nil::crypto3::detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(array_a_intermediate, left_bv.begin());

    nil::crypto3::detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(array_b_intermediate, right_bv.begin());

    nil::crypto3::detail::pack_to<stream_endian::big_octet_big_bit, 32, 1>(array_c_intermediate, hash_bv.begin());

    left.generate_assignments(left_bv);

    right.generate_assignments(right_bv);

    f.generate_assignments();
    output.generate_assignments(hash_bv);

    BOOST_CHECK(bp.is_satisfied());

    return bp;
}

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_SHA256_COMPONENT_TEST_HPP
