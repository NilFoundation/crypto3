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

#ifndef CRYPTO3_ZK_PLONK_BATCHED_KATE_PARAMS_HPP
#define CRYPTO3_ZK_PLONK_BATCHED_KATE_PARAMS_HPP

#include <memory>

#include <nil/crypto3/hash/keccak.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename Hash = hashes::keccak<256>>
                struct standard_settings {
                    constexpr static const std::size_t num_challenge_bytes = 32;
                    constexpr static const transcript::HashType hash_type = transcript::HashType::Keccak256;
                    constexpr static const std::size_t program_width = 3;
                    constexpr static const std::size_t num_shifted_wire_evaluations = 1;
                    constexpr static const std::uint64_t wire_shift_settings = 0b0100;
                    constexpr static const bool uses_quotient_mid = false;
                    constexpr static const std::uint32_t permutation_shift = 30;
                    constexpr static const std::uint32_t permutation_mask = 0xC0000000;
                    constexpr static const bool use_linearisation = true;
                    constexpr static const std::size_t num_roots_cut_out_of_vanishing_polynomial = 4;
                };

                template<typename Hash = hashes::blake2s>
                struct unrolled_standard_settings {
                    constexpr static const size_t num_challenge_bytes = 16;
                    constexpr static const transcript::HashType hash_type = transcript::HashType::PedersenBlake2s;
                    constexpr static const size_t program_width = 3;
                    constexpr static const size_t num_shifted_wire_evaluations = 1;
                    constexpr static const uint64_t wire_shift_settings = 0b0100;
                    constexpr static const bool uses_quotient_mid = false;
                    constexpr static const uint32_t permutation_shift = 30;
                    constexpr static const uint32_t permutation_mask = 0xC0000000;
                    constexpr static const bool use_linearisation = false;
                    constexpr static const size_t num_roots_cut_out_of_vanishing_polynomial = 4;
                };

                template<typename Hash = hashes::keccak<256>>
                struct turbo_settings {
                    constexpr static const size_t num_challenge_bytes = 32;
                    constexpr static const transcript::HashType hash_type = transcript::HashType::Keccak256;
                    constexpr static const size_t program_width = 4;
                    constexpr static const size_t num_shifted_wire_evaluations = 4;
                    constexpr static const uint64_t wire_shift_settings = 0b1111;
                    constexpr static const bool uses_quotient_mid = false;
                    constexpr static const uint32_t permutation_shift = 30;
                    constexpr static const uint32_t permutation_mask = 0xC0000000;
                    constexpr static const bool use_linearisation = true;
                    constexpr static const size_t num_roots_cut_out_of_vanishing_polynomial = 4;
                };

                template<typename Hash = hashes::blake2s>
                class unrolled_turbo_settings {
                public:
                    constexpr static const size_t num_challenge_bytes = 16;
                    constexpr static const transcript::HashType hash_type = transcript::HashType::PedersenBlake2s;
                    constexpr static const size_t program_width = 4;
                    constexpr static const size_t num_shifted_wire_evaluations = 4;
                    constexpr static const uint64_t wire_shift_settings = 0b1111;
                    constexpr static const bool uses_quotient_mid = false;
                    constexpr static const uint32_t permutation_shift = 30;
                    constexpr static const uint32_t permutation_mask = 0xC0000000;
                    constexpr static const bool use_linearisation = false;
                    constexpr static const size_t num_roots_cut_out_of_vanishing_polynomial = 4;
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_BATCHED_KATE_PARAMS_HPP
