//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_HASH_H2F_SUITES_HPP
#define CRYPTO3_HASH_H2F_SUITES_HPP

#include <cstdint>

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            template<typename Field, typename Hash, std::size_t k>
            struct h2f_suite;

            template<>
            struct h2f_suite<typename algebra::curves::bls12_381::base_field_type, sha2<256>, 128> {
                typedef typename algebra::curves::bls12_381::base_field_type field_type;
                typedef typename field_type::value_type field_value_type;
                typedef typename field_type::modular_type modular_type;
                typedef sha2<256> hash_type;

                // BLS12381G1_XMD:SHA-256_SSWU_RO_
                constexpr static std::array<std::uint8_t, 31> suite_id = {66, 76, 83, 49, 50, 51, 56, 49, 71, 49, 95,
                                                                          88, 77, 68, 58, 83, 72, 65, 45, 50, 53, 54,
                                                                          95, 83, 83, 87, 85, 95, 82, 79, 95};

                constexpr static std::size_t m = field_type::arity;
                constexpr static std::size_t k = 128;
                /// L = ceil((ceil(log2(p)) + k) / 8)
                constexpr static std::size_t L = 64;
            };

            template<>
            struct h2f_suite<typename algebra::fields::fp2<typename algebra::curves::bls12_381::base_field_type>,
                             sha2<256>, 128> {
                typedef typename algebra::curves::bls12_381::g2_type<>::field_type field_type;
                typedef typename field_type::value_type field_value_type;
                typedef typename field_type::modular_type modular_type;
                typedef sha2<256> hash_type;

                // BLS12381G2_XMD:SHA-256_SSWU_RO_
                constexpr static std::array<std::uint8_t, 31> suite_id = {
                    0x42, 0x4c, 0x53, 0x31, 0x32, 0x33, 0x38, 0x31, 0x47, 0x32, 0x5f, 0x58, 0x4d, 0x44, 0x3a, 0x53,
                    0x48, 0x41, 0x2d, 0x32, 0x35, 0x36, 0x5f, 0x53, 0x53, 0x57, 0x55, 0x5f, 0x52, 0x4f, 0x5f};

                constexpr static std::size_t m = field_type::arity;
                constexpr static std::size_t k = 128;
                /// L = ceil((ceil(log2(p)) + k) / 8)
                constexpr static std::size_t L = 64;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_H2F_SUITES_HPP
