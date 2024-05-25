//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_SHA3_FUNCTIONS_HPP
#define CRYPTO3_SHA3_FUNCTIONS_HPP

#include <nil/crypto3/hash/detail/keccak/keccak_impl.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_policy.hpp>

#include <array>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<std::size_t DigestBits>
                struct sha3_functions : public sha3_policy<DigestBits> {
                    using policy_type = sha3_policy<DigestBits>;

                    constexpr static const std::size_t word_bits = policy_type::word_bits;
                    using word_type = typename policy_type::word_type;

                    constexpr static const std::size_t block_words = policy_type::block_words;
                    using block_type = typename policy_type::block_type;

                    using state_type = typename policy_type::state_type;

                    constexpr static const std::size_t round_constants_size = policy_type::rounds;
                    using round_constants_type = typename std::array<word_type, round_constants_size>;

                    constexpr static const std::size_t pkcs_id_size = policy_type::pkcs_id_size;
                    constexpr static const std::size_t pkcs_id_bits = policy_type::pkcs_id_bits;
                    using pkcs_id_type = typename policy_type::pkcs_id_type;

                    constexpr static const pkcs_id_type pkcs_id = policy_type::pkcs_id;

                    static void permute(state_type &A) {
                        keccak_1600_impl<policy_type>::permute(A);
                    }

                    static void absorb(const block_type& block, state_type& state) {
                        for (std::size_t i = 0; i < block.size(); ++i) {
                            // XOR
                            state[i] ^= block[i];
                        }
                    }
                };
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SHA3_FUNCTIONS_HPP
