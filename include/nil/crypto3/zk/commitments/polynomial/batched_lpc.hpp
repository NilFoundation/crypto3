//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#ifndef CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_batched_fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/lpc.hpp>
#include <nil/crypto3/zk/commitments/polynomial/fri.hpp>
#include <nil/crypto3/zk/commitments/polynomial/batched_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                /**
                 * @brief Based on the FRI Commitment description from \[ResShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[Placeholder].
                 *
                 * References:
                 * \[Placeholder]:
                 * "PLACEHOLDER: Transparent SNARKs from List
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template<typename FieldType, typename LPCParams, std::size_t BatchSize = 1, bool IsRunTimeSize = false>
                struct batched_list_polynomial_commitment;

                template<typename FieldType, typename LPCParams, std::size_t BatchSize>
                struct batched_list_polynomial_commitment<FieldType, LPCParams, BatchSize, false>
                    : public detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                       typename LPCParams::transcript_hash_type, LPCParams::m> {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;
                    constexpr static const std::size_t leaf_size = BatchSize;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                                typename LPCParams::transcript_hash_type, m>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof && T_root == rhs.T_root;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::array<std::vector<typename FieldType::value_type>, leaf_size> z;

                        commitment_type T_root;

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;
                    };
                };

                template<typename FieldType, typename LPCParams>
                struct batched_list_polynomial_commitment<FieldType, LPCParams, 0, true>
                    : public detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                       typename LPCParams::transcript_hash_type, LPCParams::m> {

                    using merkle_hash_type = typename LPCParams::merkle_hash_type;

                    constexpr static const std::size_t lambda = LPCParams::lambda;
                    constexpr static const std::size_t r = LPCParams::r;
                    constexpr static const std::size_t m = LPCParams::m;

                    typedef LPCParams lpc_params;

                    typedef typename containers::merkle_proof<merkle_hash_type, 2> merkle_proof_type;

                    using basic_fri = detail::basic_batched_fri<FieldType, typename LPCParams::merkle_hash_type,
                                                                typename LPCParams::transcript_hash_type, m>;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;

                    struct proof_type {
                        bool operator==(const proof_type &rhs) const {
                            return z == rhs.z && fri_proof == rhs.fri_proof && T_root == rhs.T_root;
                        }
                        bool operator!=(const proof_type &rhs) const {
                            return !(rhs == *this);
                        }

                        std::vector<std::vector<typename FieldType::value_type>> z;

                        commitment_type T_root;

                        std::array<typename basic_fri::proof_type, lambda> fri_proof;
                    };
                };

                template<typename FieldType, typename LPCParams, std::size_t BatchSize, bool IsRunTimeSize = false>
                using batched_lpc = batched_list_polynomial_commitment<FieldType, LPCParams, BatchSize, IsRunTimeSize>;
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BATCHED_LIST_POLYNOMIAL_COMMITMENT_SCHEME_HPP
