//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
                template<typename FieldType,
                        typename MerkleTreeHashType,
                        typename TranscriptHashType,
                        std::size_t Lambda,
                        std::size_t M,
                        bool UseGrinding =false,
                        typename GrindingType = proof_of_work<TranscriptHashType>
                >
                struct fri : public detail::basic_batched_fri<FieldType,
                        MerkleTreeHashType,
                        TranscriptHashType,
                        Lambda, M,
                        UseGrinding, GrindingType
                > {
                    using basic_fri = detail::basic_batched_fri<FieldType,
                            MerkleTreeHashType,
                            TranscriptHashType,
                            Lambda, M, UseGrinding, GrindingType>;
                    constexpr static const std::size_t m = basic_fri::m;
                    constexpr static const std::size_t batches_num = basic_fri::batches_num;

                    using field_type = typename basic_fri::field_type;
                    using merkle_tree_hash_type = typename basic_fri::merkle_tree_hash_type;
                    using transcript_hash_type = typename basic_fri::transcript_hash_type;
                    using merkle_tree_type = typename basic_fri::merkle_tree_type;
                    using merkle_proof_type = typename basic_fri::merkle_proof_type;
                    using proof_type = typename basic_fri::proof_type;
                    using params_type = typename basic_fri::params_type;
                    using transcript_type = typename basic_fri::transcript_type;

                    using precommitment_type = typename basic_fri::precommitment_type;
                    using commitment_type = typename basic_fri::commitment_type;
                };
            }    // namespace commitments

            namespace algorithms {
                // Proof and verify for one polynomial
                // One polynomial processing
                template<typename FRI,
                    typename PolynomialType,
                    typename std::enable_if<std::is_base_of<commitments::fri<typename FRI::field_type,
                            typename FRI::merkle_tree_hash_type,
                            typename FRI::transcript_hash_type,
                            FRI::lambda, FRI::m,
                            FRI::use_grinding,
                            typename FRI::grinding_type
                        >,
                        FRI>::value,
                    bool>::type = true>
                static typename FRI::basic_fri::proof_type proof_eval(
                    PolynomialType &g,
                    typename FRI::basic_fri::merkle_tree_type &tree,
                    const typename FRI::params_type &fri_params,
                    typename FRI::transcript_type &transcript = typename FRI::transcript_type()
                ){
                    std::map<std::size_t, std::vector<PolynomialType>> gs;
                    gs[0]={g};
                    std::map<std::size_t, typename FRI::basic_fri::merkle_tree_type> trees;
                    trees[0] = typename FRI::basic_fri::merkle_tree_type(tree);
                    return proof_eval<FRI, PolynomialType>(gs, g, trees, tree, fri_params, transcript);
                }

                template<typename FRI,
                    typename std::enable_if<
                        std::is_base_of<commitments::detail::basic_batched_fri<
                            typename FRI::field_type,
                            typename FRI::merkle_tree_hash_type,
                            typename FRI::transcript_hash_type,
                            FRI::lambda, FRI::m,
                            FRI::use_grinding,
                            typename FRI::grinding_type
                        >,
                        FRI>::value,
                        bool>::type = true>
                static bool verify_eval(
                    const typename FRI::basic_fri::proof_type &proof,
                    const typename FRI::basic_fri::commitment_type &t_root,
                    const typename FRI::basic_fri::params_type &fri_params,
                    typename FRI::basic_fri::transcript_type &transcript = typename FRI::basic_fri::transcript_type()
                ) {
                    std::map<std::size_t, typename FRI::basic_fri::commitment_type> t_roots; t_roots[0] = {t_root};
                    std::vector<std::vector<std::tuple<std::size_t, std::size_t>>> evals_map(1); evals_map[0] = {{0,0}};

                    std::vector<typename FRI::field_type::value_type> combined_U = {0};
                    std::vector<math::polynomial<typename FRI::field_type::value_type>> combined_V = {{1}};

                    return verify_eval<typename FRI::basic_fri>(
                            proof, fri_params, t_roots,
                            FRI::basic_fri::field_type::value_type::one(),
                            evals_map, combined_U, combined_V,
                            transcript
                    );
                }
            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_FRI_COMMITMENT_SCHEME_HPP
