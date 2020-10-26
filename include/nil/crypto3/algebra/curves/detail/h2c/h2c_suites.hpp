//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP
#define CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP

#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/algebra/curves/detail/h2c/h2c_utils.hpp>

#include <cstdint>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                    template<typename GroupType>
                    struct h2c_suite;

                    template<>
                    struct h2c_suite<typename bls12_381::g1_type> {
                        typedef bls12_381 group_policy_type;
                        typedef hashes::sha2<256> hash_policy_type;

                        typedef typename group_policy_type::g1_type group_value_type;
                        typedef typename group_policy_type::number_type number_type;
                        typedef typename group_value_type::underlying_field_value_type field_value_type;

                        // BLS12381G1_XMD:SHA-256_SSWU_RO_
                        constexpr static std::array<std::uint8_t, 31> suite_id = {
                            66, 76, 83, 49, 50, 51, 56, 49, 71, 49, 95, 88, 77, 68, 58, 83,
                            72, 65, 45, 50, 53, 54, 95, 83, 83, 87, 85, 95, 82, 79, 95};
                        constexpr static number_type p = group_policy_type::p;
                        constexpr static std::size_t m = 1;
                        constexpr static std::size_t k = 128;
                        constexpr static std::size_t L = 64;

                        typedef expand_message_xmd<hash_policy_type> expand_message;
                    };
                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_HASH_TO_CURVE_SUITES_HPP
