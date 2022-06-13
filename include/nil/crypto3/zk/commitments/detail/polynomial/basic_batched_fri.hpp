//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {

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
                    template<typename FieldType, typename MerkleTreeHashType, typename TranscriptHashType,
                             std::size_t M = 2>
                    struct basic_batched_fri {

                        constexpr static const std::size_t m = M;

                        typedef FieldType field_type;
                        typedef MerkleTreeHashType merkle_tree_hash_type;
                        typedef TranscriptHashType transcript_hash_type;

                        typedef typename containers::merkle_tree<MerkleTreeHashType, 2> merkle_tree_type;
                        typedef typename containers::merkle_proof<MerkleTreeHashType, 2> merkle_proof_type;

                        using Endianness = nil::marshalling::option::big_endian;
                        using field_element_type =
                            nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<Endianness>,
                                                                            typename FieldType::value_type>;

                        using precommitment_type = merkle_tree_type;
                        using commitment_type = typename precommitment_type::value_type;
                        using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
                        using params_type =
                            typename basic_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M>::params_type;

                        struct round_proof_type {
                            // bool operator==(const round_proof_type &rhs) const {
                            //     return y == rhs.y && p == rhs.p && T_root == rhs.T_root &&
                            //            colinear_value == rhs.colinear_value && colinear_path == rhs.colinear_path;
                            // }
                            // bool operator!=(const round_proof_type &rhs) const {
                            //     return !(rhs == *this);
                            // }
                            // std::array<std::array<typename FieldType::value_type, m>, leaf_size> y;
                            std::vector<std::array<typename FieldType::value_type, m>> y;
                            std::array<merkle_proof_type, m> p;

                            typename merkle_tree_type::value_type T_root;

                            // std::array<typename FieldType::value_type, leaf_size> colinear_value;
                            std::vector<typename FieldType::value_type> colinear_value;
                            merkle_proof_type colinear_path;
                        };

                        struct proof_type {
                            // bool operator==(const proof_type &rhs) const {
                            //     return round_proofs == rhs.round_proofs && final_polynomials ==
                            //     rhs.final_polynomials;
                            // }
                            // bool operator!=(const proof_type &rhs) const {
                            //     return !(rhs == *this);
                            // }

                            std::vector<round_proof_type> round_proofs;    // 0..r-2

                            // std::array<math::polynomial<typename FieldType::value_type>,
                            //     leaf_size> final_polynomials;
                            std::vector<math::polynomial<typename FieldType::value_type>> final_polynomials;

                            commitment_type target_commitment;
                        };
                    };
                }    // namespace detail
            }        // namespace commitments
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_BATCHED_FRI_HPP
