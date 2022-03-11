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

#ifndef CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
#define CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/basic_fri.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {

                /**
                 * @brief Based on the FRI Commitment description from \[ResShift].
                 * @tparam d ...
                 * @tparam Rounds Denoted by r in \[RedShift].
                 *
                 * References:
                 * \[RedShift]:
                 * "REDSHIFT: Transparent SNARKs from List
                 * Polynomial Commitment IOPs",
                 * Assimakis Kattis, Konstantin Panarin, Alexander Vlasov,
                 * Matter Labs,
                 * <https://eprint.iacr.org/2019/1400.pdf>
                 */
                template<typename FieldType,
                         typename MerkleTreeHashType,
                         typename TranscriptHashType,
                         std::size_t M = 2>
                class fri : public detail::basic_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M> {

                    using basic_fri = detail::basic_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M>;

                public:
                    constexpr static const std::size_t m = basic_fri::m;

                    using field_type = typename basic_fri::field_type;
                    using merkle_tree_hash_type = typename basic_fri::merkle_tree_hash_type;
                    using transcript_hash_type = typename basic_fri::transcript_hash_type;
                    using proof_type = typename basic_fri::proof_type;
                    using params_type = typename basic_fri::params_type;
                    using transcript_type = typename basic_fri::transcript_type;
                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;

                    static typename basic_fri::proof_type proof_eval(
                        const math::polynomial<typename FieldType::value_type> &g,
                        precommitment_type &T,
                        const typename basic_fri::params_type &fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        return basic_fri::proof_eval(g, g, T, fri_params, transcript);
                    }

                    static bool verify_eval(
                        typename basic_fri::proof_type &proof,
                        typename basic_fri::params_type &fri_params,
                        typename basic_fri::transcript_type &transcript = typename basic_fri::transcript_type()) {

                        math::polynomial<typename FieldType::value_type> U = {0};
                        math::polynomial<typename FieldType::value_type> V = {1};
                        return basic_fri::verify_eval(proof, fri_params, U, V, transcript);
                    }
                };
            }    // namespace commitments
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
