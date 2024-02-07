//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP
#define CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP

#include <memory>
#include <unordered_map>
#include <map>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/proof_of_work.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/placeholder/detail/placeholder_scoped_profiler.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace commitments {
                namespace detail {
                    template<typename T>
                    struct TD;
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
                            std::size_t Lambda, std::size_t M, bool UseGrinding = false,
                            typename GrindingType = nil::crypto3::zk::commitments::proof_of_work<TranscriptHashType>>
                    struct basic_batched_fri {
                        BOOST_STATIC_ASSERT_MSG(M == 2, "unsupported m value!");

                        constexpr static const std::size_t m = M;
                        constexpr static const std::size_t lambda = Lambda;

                        constexpr static const bool use_grinding = UseGrinding;
                        using grinding_type = GrindingType;

                        typedef FieldType field_type;
                        typedef MerkleTreeHashType merkle_tree_hash_type;
                        typedef TranscriptHashType transcript_hash_type;

                        typedef std::array<typename field_type::value_type, m> polynomial_value_type;
                        typedef std::vector<polynomial_value_type> polynomial_values_type;

                        // For initial proof only, size of all values are similar
                        typedef std::vector<polynomial_values_type> polynomials_values_type;

                        using Endianness = nil::marshalling::option::big_endian;
                        using field_element_type = nil::crypto3::marshalling::types::field_element<
                                nil::marshalling::field_type<Endianness>,
                                typename FieldType::value_type
                        >;

                        using merkle_tree_type = containers::merkle_tree<MerkleTreeHashType, 2>;
                        using merkle_proof_type =  typename containers::merkle_proof<MerkleTreeHashType, 2>;
                        using precommitment_type = merkle_tree_type;
                        using commitment_type = typename precommitment_type::value_type;
                        using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;
                        using polynomial_type = math::polynomial<typename FieldType::value_type>;

                        struct params_type {

                            using field_type = FieldType;
                            using merkle_tree_type = containers::merkle_tree<MerkleTreeHashType, 2>;
                            using merkle_proof_type =  typename containers::merkle_proof<MerkleTreeHashType, 2>;
                            using precommitment_type = merkle_tree_type;
                            using commitment_type = typename precommitment_type::value_type;
                            using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;

                            // We need these constants duplicated here, so we can access them from marshalling easier. Everything that
                            // needs to be marshalled is a part of params_type.
                            using grinding_type = GrindingType;

                            constexpr static std::size_t lambda = Lambda;
                            constexpr static std::size_t m = M;
                            constexpr static bool use_grinding = UseGrinding;

                            params_type(const params_type &other) = default;
                            params_type() = default;
                            params_type(
                                std::size_t max_degree,
                                std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D,
                                std::vector<std::size_t> step_list_in,
                                std::size_t expand_factor
                            ) : max_degree(max_degree)
                              , D(D)
                              , r(std::accumulate(step_list_in.begin(), step_list_in.end(), 0))
                              , step_list(step_list_in)
                              , expand_factor(expand_factor)
                            {}

                            bool operator==(const params_type &rhs) const {
                                return r == rhs.r && max_degree == rhs.max_degree && D == rhs.D && step_list == rhs.step_list;
                            }

                            bool operator!=(const params_type &rhs) const {
                                return !(rhs == *this);
                            }

                            const std::size_t max_degree;
                            const std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;

                            // The total number of FRI-rounds, the sum of 'step_list'.
                            const std::size_t r;
                            const std::vector<std::size_t> step_list;

                            // Degrees of D are degree_log + expand_factor. This is unused in FRI,
                            // but we still want to keep the parameter with which it was constructed.
                            const std::size_t expand_factor;
                        };

                        struct round_proof_type {
                            bool operator==(const round_proof_type &rhs) const {
                                return p == rhs.p && y == rhs.y;
                            }

                            bool operator!=(const round_proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            // For the last round it's final_polynomial's values
                            polynomial_values_type               y;                         // Values for the next round.
                            merkle_proof_type                    p;                         // Merkle proof(values[i-1], T_i)
                        };

                        struct initial_proof_type {
                            bool operator==(const initial_proof_type &rhs) const {
                                return values == rhs.values && p == rhs.p;
                            }

                            bool operator!=(const initial_proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            polynomials_values_type values;
                            merkle_proof_type p;
                        };

                        struct query_proof_type {
                            bool operator==(const query_proof_type &rhs) const {
                                return initial_proof == rhs.initial_proof && round_proofs == rhs.round_proofs;
                            }

                            bool operator!=(const query_proof_type &rhs) const {
                                return !(rhs == *this);
                            }
                            std::map<std::size_t, initial_proof_type> initial_proof;
                            std::vector<round_proof_type> round_proofs;
                        };

                        struct proof_type {
                            bool operator==(const proof_type &rhs) const {
//                                if( FRI::use_grinding && proof_of_work != rhs.proof_of_work ){
//                                    return false;
//                                }
                                return fri_roots == rhs.fri_roots &&
                                       query_proofs == rhs.query_proofs &&
                                       final_polynomial == rhs.final_polynomial;
                            }

                            bool operator!=(const proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            std::vector<commitment_type>                        fri_roots;        // 0,..step_list.size()
                            math::polynomial<typename field_type::value_type>   final_polynomial;
                            std::array<query_proof_type, lambda>                query_proofs;     // 0...lambda - 1
                            typename GrindingType::output_type                  proof_of_work;
                        };
                    };
                    template <typename FRI>
                    constexpr bool use_grinding()
                    {
                        return FRI::use_grinding;
                    }
                }    // namespace detail
            }        // namespace commitments

            namespace algorithms {
                template<typename FRI,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::lambda, FRI::m,
                                FRI::use_grinding, typename FRI::grinding_type
                            >,
                            FRI
                        >::value,
                        bool
                    >::type = true>
                static typename FRI::commitment_type commit(const typename FRI::precommitment_type &P) {
                    return P.root();
                }

                template<typename FRI, std::size_t list_size,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::lambda, FRI::m,
                                FRI::use_grinding, typename FRI::grinding_type
                            >,
                            FRI>::value,
                        bool>::type = true>
                static std::array<typename FRI::commitment_type, list_size>
                commit(const std::array<typename FRI::precommitment_type, list_size> &P) {

                    std::array<typename FRI::commitment_type, list_size> commits;
                    for (std::size_t i = 0; i < list_size; i++) {
                        commits[i] = commit(P);
                    }
                    return commits;
                }

                template<typename FRI>
                static inline std::size_t get_paired_index(const std::size_t x_index, const std::size_t domain_size) {
                    return (x_index + domain_size / FRI::m) % domain_size;
                }

                template<typename FRI,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type,
                                typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type,
                                FRI::lambda, FRI::m,
                                FRI::use_grinding, typename FRI::grinding_type
                            >,
                            FRI>::value,
                        bool>::type = true>
                static typename FRI::precommitment_type
                precommit(math::polynomial_dfs<typename FRI::field_type::value_type> &f,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> D,
                          const std::size_t fri_step) {

                    if (f.size() != D->size()) {
                        f.resize(D->size(), nullptr, D);
                    }
                    std::size_t domain_size = D->size();
                    std::size_t coset_size = 1 << fri_step;
                    std::size_t leafs_number = domain_size / coset_size;
                    std::size_t leaf_bytes = coset_size * FRI::field_element_type::length();
                    std::vector<std::vector<std::uint8_t>> y_data(leafs_number, std::vector<std::uint8_t>(leaf_bytes));

                    for (std::size_t x_index = 0; x_index < leafs_number; x_index++) {
                        std::vector<std::array<std::size_t, FRI::m>> s_indices(coset_size / FRI::m);
                        s_indices[0][0] = x_index;
                        s_indices[0][1] = get_paired_index<FRI>(x_index, domain_size);

                        auto write_iter = y_data[x_index].begin();
                        typename FRI::field_element_type y_val0(f[s_indices[0][0]]);
                        y_val0.write(write_iter, FRI::field_element_type::length());
                        typename FRI::field_element_type y_val1(f[s_indices[0][1]]);
                        y_val1.write(write_iter, FRI::field_element_type::length());

                        std::size_t base_index = domain_size / (FRI::m * FRI::m);
                        std::size_t prev_half_size = 1;
                        std::size_t i = 1;
                        while (i < coset_size / FRI::m) {
                            for (std::size_t j = 0; j < prev_half_size; j++) {
                                s_indices[i][0] = (base_index + s_indices[j][0]) % domain_size;
                                s_indices[i][1] = get_paired_index<FRI>(s_indices[i][0], domain_size);

                                typename FRI::field_element_type y_val0(f[s_indices[i][0]]);
                                y_val0.write(write_iter, FRI::field_element_type::length());
                                typename FRI::field_element_type y_val1(f[s_indices[i][1]]);
                                y_val1.write(write_iter, FRI::field_element_type::length());

                                i++;
                            }
                            base_index /= FRI::m;
                            prev_half_size <<= 1;
                        }
                    }

                    return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(y_data.begin(),
                                                                                                     y_data.end());
                }

                template<typename FRI,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::detail::basic_batched_fri<
                                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                typename FRI::transcript_hash_type,
                                                FRI::lambda, FRI::m,
                                                FRI::use_grinding, typename FRI::grinding_type
                                        >,
                                        FRI>::value,
                                bool>::type = true>
                static typename FRI::precommitment_type
                precommit(const math::polynomial<typename FRI::field_type::value_type> &f,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>>
                          D,
                          const std::size_t fri_step) {

                    math::polynomial_dfs<typename FRI::field_type::value_type> f_dfs;
                    f_dfs.from_coefficients(f);

                    return precommit<FRI>(f_dfs, D, fri_step);
                }

                template<typename FRI, typename ContainerType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::detail::basic_batched_fri<
                                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                typename FRI::transcript_hash_type, FRI::lambda, FRI::m,
                                                FRI::use_grinding, typename FRI::grinding_type>,
                                        FRI>::value,
                                bool>::type = true>
                static typename std::enable_if<
                        (std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FRI::field_type::value_type>>::value),
                        typename FRI::precommitment_type>::type
                precommit(ContainerType poly,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> D,
                          const std::size_t fri_step
                ) {
                    PROFILE_PLACEHOLDER_SCOPE("Basic FRI Precommit time");

                    for (std::size_t i = 0; i < poly.size(); ++i) {
                        if (poly[i].size() != D->size()) {
                            poly[i].resize(D->size(), nullptr, D);
                        }
                    }

                    std::size_t domain_size = D->size();
                    std::size_t list_size = poly.size();
                    std::size_t coset_size = 1 << fri_step;
                    std::size_t leafs_number = domain_size / coset_size;
                    std::vector<std::vector<std::uint8_t>> y_data(
                            leafs_number,
                            std::vector<std::uint8_t>(coset_size * FRI::field_element_type::length() * list_size));

                    for (std::size_t x_index = 0; x_index < leafs_number; x_index++) {
                        auto write_iter = y_data[x_index].begin();
                        for (std::size_t polynom_index = 0; polynom_index < list_size; polynom_index++) {
                            std::vector<std::array<std::size_t, FRI::m>> s_indices(coset_size / FRI::m);
                            s_indices[0][0] = x_index;
                            s_indices[0][1] = get_paired_index<FRI>(x_index, domain_size);

                            typename FRI::field_element_type y_val0(poly[polynom_index][s_indices[0][0]]);
                            y_val0.write(write_iter, FRI::field_element_type::length());
                            typename FRI::field_element_type y_val1(poly[polynom_index][s_indices[0][1]]);
                            y_val1.write(write_iter, FRI::field_element_type::length());

                            std::size_t base_index = domain_size / (FRI::m * FRI::m);
                            std::size_t prev_half_size = 1;
                            std::size_t i = 1;
                            while (i < coset_size / FRI::m) {
                                for (std::size_t j = 0; j < prev_half_size; j++) {
                                    s_indices[i][0] = (base_index + s_indices[j][0]) % domain_size;
                                    s_indices[i][1] = get_paired_index<FRI>(s_indices[i][0], domain_size);
                                    typename FRI::field_element_type y_val0(poly[polynom_index][s_indices[i][0]]);
                                    y_val0.write(write_iter, FRI::field_element_type::length());
                                    typename FRI::field_element_type y_val1(poly[polynom_index][s_indices[i][1]]);
                                    y_val1.write(write_iter, FRI::field_element_type::length());

                                    i++;
                                }
                                base_index /= FRI::m;
                                prev_half_size <<= 1;
                            }
                        }
                    }

                    return containers::make_merkle_tree<typename FRI::merkle_tree_hash_type, FRI::m>(y_data.begin(),
                                                                                                     y_data.end());
                }

                template<typename FRI, typename ContainerType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::detail::basic_batched_fri<
                                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                typename FRI::transcript_hash_type,
                                                FRI::lambda, FRI::m,
                                                FRI::use_grinding, typename FRI::grinding_type>,
                                        FRI>::value,
                                bool>::type = true>
                static typename std::enable_if<
                        (std::is_same<typename ContainerType::value_type,
                                math::polynomial<typename FRI::field_type::value_type>>::value),
                        typename FRI::precommitment_type>::type
                precommit(const ContainerType &poly,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>>
                          D,
                          const std::size_t fri_step
                ) {
                    std::size_t list_size = poly.size();
                    std::vector<math::polynomial_dfs<typename FRI::field_type::value_type>> poly_dfs(list_size);
                    for (std::size_t i = 0; i < list_size; i++) {
                        poly_dfs[i].from_coefficients(poly[i]);
                        poly_dfs[i].resize(D->size(), nullptr, D);
                    }

                    return precommit<FRI>(poly_dfs, D, fri_step);
                }

                template<typename FRI>
                static inline typename FRI::merkle_proof_type
                make_proof_specialized(const std::size_t x_index, const std::size_t domain_size,
                                       const typename FRI::merkle_tree_type &tree) {
                    std::size_t min_x_index = std::min(x_index, get_paired_index<FRI>(x_index, domain_size));
                    return typename FRI::merkle_proof_type(tree, min_x_index);
                }

                template<typename FRI>
                static inline std::size_t get_folded_index(std::size_t x_index, std::size_t domain_size,
                                                           const std::size_t fri_step) {
                    for (std::size_t i = 0; i < fri_step; i++) {
                        domain_size /= FRI::m;
                        x_index %= domain_size;
                    }
                    return x_index;
                }

                template<typename FRI>
                static inline bool check_step_list(const typename FRI::params_type &fri_params) {
                    if (fri_params.step_list.empty()) {
                        // step_list must not be empty
                        return false;
                    }
                    std::size_t cumulative_fri_step = 0;
                    for (std::size_t i = 0; i < fri_params.step_list.size(); ++i) {
                        if (!(fri_params.step_list[i] > 0 /* || i == 0*/)) {
                            // step_list at each layer must be at least 1
                            return false;
                        }
                        if (fri_params.step_list[i] > 10) {
                            // step_list at each layer cannot be greater than 10
                            return false;
                        }
                        cumulative_fri_step += fri_params.step_list[i];
                    }
                    if (cumulative_fri_step != fri_params.r) {
                        // FRI total reduction cannot be greater than the trace length
                        return false;
                    }
                    if (fri_params.step_list.back() != 1) {
                        return false;
                    }
                    return true;
                }

                // TODO: add necessary checks.
                //template<typename FRI>
                //bool check_initial_precommitment(const std::array<typename FRI::precommitment_type, batches_num> &precommitments,
                //                                 const typename FRI::params_type &fri_params) {
                //    std::size_t domain_size = fri_params.D[0]->size();
                //    std::size_t coset_size = 1 << fri_params.step_list[0];
                //    std::size_t leafs_number = domain_size / coset_size;
                //    return leafs_number == precommitments[0].leaves();
                //}

                template<typename FRI>
                static inline std::pair<std::vector<std::array<typename FRI::field_type::value_type, FRI::m>>,
                        std::vector<std::array<std::size_t, FRI::m>>>
                calculate_s(const typename FRI::field_type::value_type &x, const std::size_t x_index,
                            const std::size_t fri_step,
                            std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> D) {
                    const std::size_t domain_size = D->size();
                    const std::size_t coset_size = 1 << fri_step;
                    std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s(coset_size / FRI::m);
                    std::vector<std::array<std::size_t, FRI::m>> s_indices(coset_size / FRI::m);
                    s_indices[0][0] = x_index;
                    s_indices[0][1] = get_paired_index<FRI>(s_indices[0][0], domain_size);
                    s[0][0] = D->get_domain_element(s_indices[0][0]);
                    s[0][1] = D->get_domain_element(s_indices[0][1]);
                    BOOST_ASSERT(s[0][0] == x);
                    // [0, N/4, N/8, N/8 + N/4, N/16, N/16 + N/4, N/16 + N/8, N/16 + N/8 + N/4 ...]
                    std::size_t base_index = domain_size / (FRI::m * FRI::m);
                    std::size_t prev_half_size = 1;
                    std::size_t i = 1;
                    while (i < coset_size / FRI::m) {
                        for (std::size_t j = 0; j < prev_half_size; j++) {
                            s_indices[i][0] = (base_index + s_indices[j][0]) % domain_size;
                            s_indices[i][1] = get_paired_index<FRI>(s_indices[i][0], domain_size);
                            s[i][0] = D->get_domain_element(s_indices[i][0]);
                            s[i][1] = D->get_domain_element(s_indices[i][1]);
                            i++;
                        }
                        base_index /= FRI::m;
                        prev_half_size <<= 1;
                    }

                    return std::make_pair(std::move(s), std::move(s_indices));
                }

                template<typename FRI>
                static inline std::vector<std::pair<std::size_t, std::size_t>>
                get_correct_order(const std::size_t x_index,
                                  const std::size_t domain_size,
                                  const std::size_t fri_step,
                                  const std::vector<std::array<std::size_t, FRI::m>> &input_s_indices) {
                    const std::size_t coset_size = 1 << fri_step;
                    BOOST_ASSERT(coset_size / FRI::m == input_s_indices.size());
                    std::vector<std::size_t> correctly_ordered_s_indices(coset_size / FRI::m);
                    correctly_ordered_s_indices[0] = get_folded_index<FRI>(x_index, domain_size, fri_step);
                    std::size_t base_index = domain_size / (FRI::m * FRI::m);
                    std::size_t prev_half_size = 1;
                    std::size_t i = 1;
                    while (i < coset_size / FRI::m) {
                        for (std::size_t j = 0; j < prev_half_size; j++) {
                            correctly_ordered_s_indices[i] =
                                    (base_index + correctly_ordered_s_indices[j]) % domain_size;
                            i++;
                        }
                        base_index /= FRI::m;
                        prev_half_size <<= 1;
                    }
                    std::vector<std::pair<std::size_t, std::size_t>> correct_order_idx(coset_size / FRI::m);
                    for (i = 0; i < coset_size / FRI::m; i++) {
                        const std::size_t paired_index = get_paired_index<FRI>(correctly_ordered_s_indices[i],
                                                                               domain_size);
                        auto found_it =
                                std::find_if(std::cbegin(input_s_indices), std::cend(input_s_indices),
                                             [&](const auto &v) {
                                                 if (v[0] == correctly_ordered_s_indices[i] &&
                                                     v[1] == paired_index) {
                                                     correct_order_idx[i].second = 0;
                                                     return true;
                                                 } else if (v[1] == correctly_ordered_s_indices[i] &&
                                                            v[0] == paired_index) {
                                                     correct_order_idx[i].second = 1;
                                                     return true;
                                                 }
                                                 return false;
                                             });
                        if (found_it != std::cend(input_s_indices)) {
                            correct_order_idx[i].first = std::distance(std::cbegin(input_s_indices), found_it);
                        } else {
                            BOOST_ASSERT(false);
                        }
                    }

                    return correct_order_idx;
                }

                template<typename FRI, typename PolynomialType,
                    typename std::enable_if<
                            std::is_base_of<
                                    commitments::detail::basic_batched_fri<
                                            typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                            typename FRI::transcript_hash_type,
                                            FRI::lambda, FRI::m,
                                            FRI::use_grinding, typename FRI::grinding_type>,
                                    FRI>::value,
                            bool>::type = true>
                static typename FRI::proof_type proof_eval(
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const PolynomialType combined_Q,
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::precommitment_type &combined_Q_precommitment,
                    const typename FRI::params_type &fri_params,
                    typename FRI::transcript_type &transcript
                ) {
                    typename FRI::proof_type proof;

                    BOOST_ASSERT(check_step_list<FRI>(fri_params));
                    // TODO: add necessary checks
                    //BOOST_ASSERT(check_initial_precommitment<FRI>(precommitments, fri_params));

                    // This resizes actually happens when called at the end of prover:
                    // _proof.eval_proof.eval_proof = _commitment_scheme.proof_eval(transcript);
                    // We DO NOT resize it here, it takes waaay too much RAM, resize it when needed.

                    //if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>, PolynomialType>::value) {
                    //    for( auto const &it:g ){
                    //        auto k = it.first;
                    //        for (int i = 0; i < g[k].size(); ++i ){
                    //            // If LPC works properly this if is never executed.
                    //            if (g[k][i].size() != fri_params.D[0]->size()) {
                    //                g[k][i].resize(fri_params.D[0]->size());
                    //            }
                    //        }
                    //    }
                    //}

                    // Commit phase
                    auto f = combined_Q;
                    auto precommitment = combined_Q_precommitment;

                    std::vector<typename FRI::precommitment_type> fri_trees;
                    std::vector<typename FRI::commitment_type> fri_roots;
                    std::vector<typename FRI::field_type::value_type> alphas;
                    std::vector<PolynomialType> fs;
                    std::size_t t = 0;

                    for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                        fs.push_back(f);
                        fri_trees.push_back(precommitment);
                        fri_roots.push_back(commit<FRI>(precommitment));
                        transcript(commit<FRI>(precommitment));
                        for (std::size_t step_i = 0; step_i < fri_params.step_list[i]; step_i++, t++) {
                            alphas.push_back(transcript.template challenge<typename FRI::field_type>());
                            // Calculate next f.
                            if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                    PolynomialType>::value) {
                                f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alphas[t],
                                                                                                   fri_params.D[t]);
                            } else {
                                f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alphas[t]);
                            }
                        }
                        if (i != fri_params.step_list.size() - 1)
                            precommitment = precommit<FRI>(f, fri_params.D[t], fri_params.step_list[i + 1]);
                    }
                    fs.push_back(f);
                    math::polynomial<typename FRI::field_type::value_type> final_polynomial;
                    if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>, PolynomialType>::value) {
                        final_polynomial = math::polynomial<typename FRI::field_type::value_type>(f.coefficients());
                    } else {
                        final_polynomial = f;
                    }

                    // Grinding
                    if( FRI::use_grinding ){
                        proof.proof_of_work = FRI::grinding_type::generate(transcript);
                    }

                    // Query phase
                    std::array<typename FRI::query_proof_type, FRI::lambda> query_proofs;

                    // If we have DFS polynomials, and we are going to resize them, better convert them to coefficients form,
                    // and compute their values in those 2 * FRI::lambda points each, which is normally 2 * 20.
                    // In case lambda becomes much larger than log(2, average polynomial size), then this will not be optimal.
                    // For lambda = 20 and 2^20 rows in assignment table, it's faster and uses less RAM.
                    std::map<std::size_t, std::vector<math::polynomial<typename FRI::field_type::value_type>>> g_coeffs;
                    if constexpr (std::is_same<
                        math::polynomial_dfs<typename FRI::field_type::value_type>,
                        PolynomialType>::value
                    ) {
                        std::unordered_map<std::size_t,
                                           std::shared_ptr<math::evaluation_domain<typename FRI::field_type>>> d_cache;
                        for (const auto &[key, poly_vector]: g) {
                            for (const auto& poly: poly_vector) {
                                if (poly.size() != fri_params.D[0]->size()) {
                                    if (d_cache.find(poly.size()) == d_cache.end()) {
                                        d_cache[poly.size()] =
                                            math::make_evaluation_domain<typename FRI::field_type>(poly.size());
                                    }
                                    g_coeffs[key].emplace_back(poly.coefficients(d_cache[poly.size()]));
                                } else {
                                    // These polynomials won't be used
                                    g_coeffs[key].emplace_back(math::polynomial<typename FRI::field_type::value_type>());
                                }
                            }
                        }
                    }

                    for (std::size_t query_id = 0; query_id < FRI::lambda; query_id++) {
                        std::size_t domain_size = fri_params.D[0]->size();
                        std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                        typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);
                        t = 0;

                        std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                        std::vector<std::array<std::size_t, FRI::m>> s_indices;
                        std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[0], fri_params.D[0]);

                        //Initial proof
                        std::map<std::size_t, typename FRI::initial_proof_type> initial_proof;
                        for (const auto &it: g) {
                            auto k = it.first;
                            initial_proof[k] = {};
                            initial_proof[k].values.resize(it.second.size());
                            std::size_t coset_size = 1 << fri_params.step_list[0];
                            BOOST_ASSERT(coset_size / FRI::m == s.size());
                            BOOST_ASSERT(coset_size / FRI::m == s_indices.size());

                            //Fill values
                            t = 0;
                            const auto& g_k = it.second; // g[k]

                            for (std::size_t polynomial_index = 0; polynomial_index < g_k.size(); ++polynomial_index) {
                                initial_proof[k].values[polynomial_index].resize(coset_size / FRI::m);
                                if constexpr (std::is_same<
                                            math::polynomial_dfs<typename FRI::field_type::value_type>,
                                            PolynomialType>::value
                                    ) {
                                    if (g_k[polynomial_index].size() == fri_params.D[0]->size()) {
                                        for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                            initial_proof[k].values[polynomial_index][j][0] = g_k[polynomial_index][s_indices[j][0]];
                                            initial_proof[k].values[polynomial_index][j][1] = g_k[polynomial_index][s_indices[j][1]];
                                        }
                                    } else {
                                        // Convert to coefficients form and evaluate. coset_size / FRI::m is usually just 1,
                                        // It makes no sense to resize in dfs form to then use just 2 values in 2 points.
                                        for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                            initial_proof[k].values[polynomial_index][j][0] = g_coeffs[k][polynomial_index].evaluate(s[j][0]);
                                            initial_proof[k].values[polynomial_index][j][1] = g_coeffs[k][polynomial_index].evaluate(s[j][1]);
                                        }
                                    }
                                } else {
                                    // Same for poly in coefficients form.
                                    for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                        initial_proof[k].values[polynomial_index][j][0] = g_k[polynomial_index].evaluate(s[j][0]);
                                        initial_proof[k].values[polynomial_index][j][1] = g_k[polynomial_index].evaluate(s[j][1]);
                                    }
                                }
                            }

                            // Fill merkle proofs
                            initial_proof[k].p = make_proof_specialized<FRI>(
                                get_folded_index<FRI>(x_index, fri_params.D[0]->size(), fri_params.step_list[0]),
                                fri_params.D[0]->size(), precommitments.at(k)
                            );
                        }

                        // Fill query proofs
                        std::vector<typename FRI::round_proof_type> round_proofs;
                        t = 0;
                        round_proofs.resize(fri_params.step_list.size());
                        for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                            domain_size = fri_params.D[t]->size();
                            x_index %= domain_size;
                            x = fri_params.D[t]->get_domain_element(x_index);
                            round_proofs[i].p = make_proof_specialized<FRI>(
                                    get_folded_index<FRI>(x_index, domain_size, fri_params.step_list[i]),
                                    domain_size, fri_trees[i]
                            );

                            t += fri_params.step_list[i];
                            if (i < fri_params.step_list.size() - 1) {
                                x_index %= fri_params.D[t]->size();
                                x = fri_params.D[t]->get_domain_element(x_index);
                                std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[i + 1],
                                                                          fri_params.D[t]);

                                std::size_t coset_size = 1 << fri_params.step_list[i + 1];
                                BOOST_ASSERT(coset_size / FRI::m == s.size());
                                BOOST_ASSERT(coset_size / FRI::m == s_indices.size());

                                round_proofs[i].y.resize(coset_size / FRI::m);
                                for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                    if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                            PolynomialType>::value) {
                                        round_proofs[i].y[j][0] = fs[i + 1][s_indices[j][0]];
                                        round_proofs[i].y[j][1] = fs[i + 1][s_indices[j][1]];
                                    } else {
                                        round_proofs[i].y[j][0] = fs[i + 1].evaluate(s[j][0]);
                                        round_proofs[i].y[j][1] = fs[i + 1].evaluate(s[j][1]);
                                    }
                                }
                            } else {
                                x_index %= fri_params.D[t - 1]->size();
                                x = fri_params.D[t - 1]->get_domain_element(x_index);
                                x = x * x;
                                round_proofs[i].y.resize(1);
                                round_proofs[i].y[0][0] = final_polynomial.evaluate(x);
                                round_proofs[i].y[0][1] = final_polynomial.evaluate(-x);
                            }
                        }
                        typename FRI::query_proof_type query_proof = {std::move(initial_proof), std::move(round_proofs)};
                        query_proofs[query_id] = std::move(query_proof);
                    }

                    proof.fri_roots = std::move(fri_roots);
                    proof.final_polynomial = std::move(final_polynomial);
                    proof.query_proofs = std::move(query_proofs);

                    return proof;//typename FRI::proof_type{fri_roots, final_polynomial, query_proofs};
                }

                template<typename FRI>
                static bool verify_eval(
                    const typename FRI::proof_type                                                      &proof,
                    const typename FRI::params_type                                                     &fri_params,
                    const std::map<std::size_t, typename FRI::commitment_type>                          &commitments,
                    const typename FRI::field_type::value_type                                          theta,
                    const std::vector<std::vector<std::tuple<std::size_t, std::size_t>>>                &poly_ids,
                    const std::vector<typename FRI::field_type::value_type>                             &combined_U,
                    const std::vector<math::polynomial<typename FRI::field_type::value_type>>           &denominators,
                    typename FRI::transcript_type &transcript
                ) {
                    BOOST_ASSERT(check_step_list<FRI>(fri_params));
                    BOOST_ASSERT(combined_U.size() == denominators.size());
                    BOOST_ASSERT(combined_U.size() == poly_ids.size());

                    // TODO: Add size correcness checks.

                    if (proof.final_polynomial.degree() >
                        std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 1) {
                        return false;
                    }

                    std::vector<typename FRI::field_type::value_type> alphas;
                    std::size_t t = 0;
                    for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                        transcript(proof.fri_roots[i]);
                        for (std::size_t step_i = 0; step_i < fri_params.step_list[i]; step_i++, t++) {
                            auto alpha = transcript.template challenge<typename FRI::field_type>();
                            alphas.push_back(alpha);
                        }
                    }

                    if(FRI::use_grinding && !FRI::grinding_type::verify(transcript, proof.proof_of_work)){
                        return false;
                    }
                    for (std::size_t query_id = 0; query_id < FRI::lambda; query_id++) {
                        const typename FRI::query_proof_type &query_proof = proof.query_proofs[query_id];

                        std::size_t domain_size = fri_params.D[0]->size();
                        std::size_t coset_size = 1 << fri_params.step_list[0];
                        std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                        typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                        std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                        std::vector<std::array<std::size_t, FRI::m>> s_indices;
                        std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[0], fri_params.D[0]);
                        auto correct_order_idx = get_correct_order<FRI>(x_index, domain_size, fri_params.step_list[0],
                                                                        s_indices);

                        // Check initial proof.
                        for( auto const &it: query_proof.initial_proof ){
                            auto k = it.first;
                            if (query_proof.initial_proof.at(k).p.root() != commitments.at(k) ) {
                                return false;
                            }

                            std::vector<std::uint8_t> leaf_data(coset_size * FRI::field_element_type::length() * query_proof.initial_proof.at(k).values.size());
                            auto write_iter = leaf_data.begin();

                            for (std::size_t i = 0; i < query_proof.initial_proof.at(k).values.size(); i++) {
                                for (auto [idx, pair_idx] : correct_order_idx) {
                                    typename FRI::field_element_type leaf_val0(
                                        query_proof.initial_proof.at(k).values[i][idx][pair_idx]
                                    );
                                    leaf_val0.write(write_iter, FRI::field_element_type::length());
                                    typename FRI::field_element_type leaf_val1(
                                        query_proof.initial_proof.at(k).values[i][idx][1-pair_idx]
                                    );
                                    leaf_val1.write(write_iter, FRI::field_element_type::length());
                                }
                            }
                            if (!query_proof.initial_proof.at(k).p.validate(leaf_data)) {
                                std::cout << "Wrong initial proof" << std::endl;
                                return false;
                            }
                        }

                        //Calculate combinedQ values
                        typename FRI::field_type::value_type theta_acc(1);
                        typename FRI::polynomial_values_type y;
                        typename FRI::polynomial_values_type combined_eval_values;
                        y.resize(coset_size / FRI::m);
                        combined_eval_values.resize(coset_size / FRI::m);
                        for (size_t j = 0; j < coset_size / FRI::m; j++) {
                            y[j][0] = FRI::field_type::value_type::zero();
                            y[j][1] = FRI::field_type::value_type::zero();
                        }
                        for( std::size_t p = 0; p < poly_ids.size(); p++){
                            typename FRI::polynomial_values_type Q;
                            Q.resize(coset_size / FRI::m);
                            for( auto const &poly_id: poly_ids[p] ){
                                for (size_t j = 0; j < coset_size / FRI::m; j++) {
                                    Q[j][0] += query_proof.initial_proof.at(std::get<0>(poly_id)).values[std::get<1>(poly_id)][j][0] * theta_acc;
                                    Q[j][1] += query_proof.initial_proof.at(std::get<0>(poly_id)).values[std::get<1>(poly_id)][j][1] * theta_acc;
                                }
                                theta_acc *= theta;
                            }
                            for (size_t j = 0; j < coset_size / FRI::m; j++) {
                                Q[j][0] -= combined_U[p];
                                Q[j][1] -= combined_U[p];
                                Q[j][0] /= denominators[p].evaluate(s[j][0]);
                                Q[j][1] /= denominators[p].evaluate(s[j][1]);
                                y[j][0] += Q[j][0];
                                y[j][1] += Q[j][1];
                            }
                        }

                        // Check round proofs
                        std::size_t t = 0;
                        typename FRI::polynomial_values_type y_next;
                        for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                            coset_size = 1 << fri_params.step_list[i];
                            if (query_proof.round_proofs[i].p.root() != proof.fri_roots[i]) return false;

                            std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[i],
                                                                      fri_params.D[t]);
                            std::vector<std::uint8_t> leaf_data(coset_size * FRI::field_element_type::length());
                            auto write_iter = leaf_data.begin();
                            auto correct_order_idx =
                                    get_correct_order<FRI>(x_index, domain_size, fri_params.step_list[i], s_indices);
                            for (auto [idx, pair_idx]: correct_order_idx) {
                                typename FRI::field_element_type leaf_val0(y[idx][pair_idx]);
                                leaf_val0.write(write_iter, FRI::field_element_type::length());
                                typename FRI::field_element_type leaf_val1(y[idx][1 - pair_idx]);
                                leaf_val1.write(write_iter, FRI::field_element_type::length());
                            }
                            if (!query_proof.round_proofs[i].p.validate(leaf_data)) {
                                std::cout << "Wrong round merkle proof on " << i << "-th round" << std::endl;
                                return false;
                            }

                            // colinear check
                            for (std::size_t step_i = 0; step_i < fri_params.step_list[i] - 1; step_i++, t++) {
                                y_next.resize(y.size() / FRI::m);

                                domain_size = fri_params.D[t]->size();
                                x_index %= domain_size;
                                x = fri_params.D[t]->get_domain_element(x_index);
                                std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[i],
                                                                          fri_params.D[t]);
                                for (std::size_t y_ind = 0; y_ind < y_next.size(); y_ind++) {
                                    std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points_l{
                                            std::make_pair(s[2 * y_ind][0], y[2 * y_ind][0]),
                                            std::make_pair(s[2 * y_ind][1], y[2 * y_ind][1]),
                                    };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_l =
                                            math::lagrange_interpolation(interpolation_points_l);
                                    y_next[y_ind][0] = interpolant_l.evaluate(alphas[t]);

                                    std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points_r{
                                            std::make_pair(s[2 * y_ind + 1][0], y[2 * y_ind + 1][0]),
                                            std::make_pair(s[2 * y_ind + 1][1], y[2 * y_ind + 1][1]),
                                    };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_r =
                                            math::lagrange_interpolation(interpolation_points_r);
                                    y_next[y_ind][1] = interpolant_r.evaluate(alphas[t]);
                                }
                                x = x * x;
                                y = y_next;
                            }
                            std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[i],
                                                                      fri_params.D[t]);

                            std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points{
                                    std::make_pair(s[0][0], y[0][0]),
                                    std::make_pair(s[0][1], y[0][1]),
                            };
                            math::polynomial<typename FRI::field_type::value_type> interpolant_poly =
                                    math::lagrange_interpolation(interpolation_points);
                            auto interpolant = interpolant_poly.evaluate(alphas[t]);
                            if (interpolant != query_proof.round_proofs[i].y[0][0]) {
                                return false;
                            }

                            // For the last round we check final polynomial nor colinear_check
                            t++;
                            y = query_proof.round_proofs[i].y;
                            if (i < fri_params.step_list.size() - 1) {
                                domain_size = fri_params.D[t]->size();
                                x_index %= domain_size;
                                x = fri_params.D[t]->get_domain_element(x_index);
                            }
                        }
                        // Final polynomial check
                        x = x * x;
                        if (y[0][0] != proof.final_polynomial.evaluate(x)) {
                            return false;
                        }
                        if (y[0][1] != proof.final_polynomial.evaluate(-x)) {
                            return false;
                        }
                    }

                    return true;
                }
            }    // namespace algorithms
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMMITMENTS_BASIC_FRI_HPP