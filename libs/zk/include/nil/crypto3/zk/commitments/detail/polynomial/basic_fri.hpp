//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
// Copyright (c) 2024 Vasiliy Olekhov <vasiliy.olekhov@nil.foundation>
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

#include <boost/log/trivial.hpp>

#include <memory>
#include <unordered_map>
#include <map>
#include <random>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/container/merkle/tree.hpp>
#include <nil/crypto3/container/merkle/proof.hpp>

#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>
#include <nil/crypto3/zk/commitments/detail/polynomial/proof_of_work.hpp>
#include <nil/crypto3/zk/detail/field_element_consumer.hpp>

#include <nil/crypto3/bench/scoped_profiler.hpp>

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
                        std::size_t M, typename GrindingType = nil::crypto3::zk::commitments::proof_of_work<TranscriptHashType>>
                    struct basic_batched_fri {
                        BOOST_STATIC_ASSERT_MSG(M == 2, "unsupported m value!");

                        constexpr static const bool is_fri = true;

                        constexpr static const std::size_t m = M;
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


                            static std::vector<std::size_t> generate_random_step_list(const std::size_t r, const int max_step) {
                                using dist_type = std::uniform_int_distribution<int>;
                                static std::random_device random_engine;

                                std::vector<std::size_t> step_list;
                                std::size_t steps_sum = 0;
                                while (steps_sum != r) {
                                    if (r - steps_sum <= max_step) {
                                        while (r - steps_sum != 1) {
                                            step_list.emplace_back(r - steps_sum - 1);
                                            steps_sum += step_list.back();
                                        }
                                        step_list.emplace_back(1);
                                        steps_sum += step_list.back();
                                    } else {
                                        step_list.emplace_back(dist_type(1, max_step)(random_engine));
                                        steps_sum += step_list.back();
                                    }
                                }
                                return step_list;
                            }

                            params_type(
                                std::size_t max_step,
                                std::size_t degree_log,
                                std::size_t lambda,
                                std::size_t expand_factor,
                                bool use_grinding = false,
                                std::size_t grinding_parameter = 16
                            ): lambda(lambda)
                              , use_grinding(use_grinding)
                              , grinding_parameter(grinding_parameter)
                              , max_degree((1 << degree_log) - 1)
                              , D(math::calculate_domain_set<FieldType>(degree_log + expand_factor, degree_log - 1))
                              , r(degree_log - 1)
                              , step_list(generate_random_step_list(r, max_step))
                              , expand_factor(expand_factor)
                            { }

                            params_type(
                                const std::vector<std::size_t>& step_list_in,
                                std::size_t degree_log,
                                std::size_t lambda,
                                std::size_t expand_factor,
                                bool use_grinding = false,
                                std::size_t grinding_parameter = 16
                            ) : lambda(lambda)
                              , use_grinding(use_grinding)
                              , grinding_parameter(grinding_parameter)
                              , max_degree((1 << degree_log) - 1)
                              , D(math::calculate_domain_set<FieldType>(
                                    degree_log + expand_factor,
                                    std::accumulate(step_list_in.begin(), step_list_in.end(), 0)))
                              , r(std::accumulate(step_list_in.begin(), step_list_in.end(), 0))
                              , step_list(step_list_in)
                              , expand_factor(expand_factor)
                            { }

                            bool operator==(const params_type &rhs) const {
                                if (D.size() != rhs.D.size()) {
                                    return false;
                                }
                                for (std::size_t i = 0; i < D.size(); i++) {
                                    if (D[i]->get_domain_element(1) != rhs.D[i]->get_domain_element(1)) {
                                        return false;
                                    }
                                }
                                if (use_grinding != rhs.use_grinding) {
                                    return false;
                                }
                                if (use_grinding && grinding_parameter != rhs.grinding_parameter) {
                                    return false;
                                }
                                return r == rhs.r
                                    && max_degree == rhs.max_degree
                                    && step_list == rhs.step_list
                                    && expand_factor == rhs.expand_factor
                                    && lambda == rhs.lambda;
                            }

                            bool operator!=(const params_type &rhs) const {
                                return !(rhs == *this);
                            }

                            constexpr static std::size_t m = M;

                            const std::size_t lambda;
                            const bool use_grinding;
                            const std::size_t grinding_parameter;
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
                           
                            // Values for the next round.
                            polynomial_values_type y;

                            // Merkle proof(values[i-1], T_i).
                            merkle_proof_type p;
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

                        struct commitments_part_of_proof {
                            bool operator==(const commitments_part_of_proof& rhs) const {
                                return fri_roots == rhs.fri_roots &&
                                       final_polynomial == rhs.final_polynomial;
                            }

                            bool operator!=(const commitments_part_of_proof& rhs) const {
                                return !(rhs == *this);
                            }

                            // Vector of size 'step_list.size()'.
                            std::vector<commitment_type>                        fri_roots;
                            math::polynomial<typename field_type::value_type>   final_polynomial;
                        };

                        struct round_proofs_batch_type {
                            bool operator==(const round_proofs_batch_type &rhs) const {
                                return round_proofs == rhs.round_proofs;
                            }

                            bool operator!=(const round_proofs_batch_type &rhs) const {
                                return !(rhs == *this);
                            }

                            // Vector of size 'lambda'.
                            std::vector<std::vector<round_proof_type>> round_proofs;
                        };

                        struct initial_proofs_batch_type {
                            bool operator==(const initial_proofs_batch_type &rhs) const {
                                return initial_proofs == rhs.initial_proofs;
                            }

                            bool operator!=(const initial_proofs_batch_type &rhs) const {
                                return !(rhs == *this);
                            }

                            // Vector of size 'lambda'.
                            std::vector<std::map<std::size_t, initial_proof_type>> initial_proofs;
                        };

                        struct proof_type {
                            proof_type() = default;
                            proof_type(const proof_type&) = default;

                            proof_type(const round_proofs_batch_type& round_proofs,
                                       const initial_proofs_batch_type& intial_proofs)
                                : fri_roots(round_proofs.fri_roots)
                                , final_polynomial(round_proofs.final_polynomial) {
                                for (std::size_t i = 0; i < intial_proofs.initial_proofs.size(); ++i) {
                                    query_proofs.emplace_back(
                                        {intial_proofs.initial_proofs[i], round_proofs.round_proofs[i]});
                                }
                            }

                            bool operator==(const proof_type &rhs) const {
                                // TODO(martun): check if the following comment can be deleted.
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
                            std::vector<query_proof_type>                       query_proofs;     // 0...lambda - 1
                            typename GrindingType::output_type                  proof_of_work;
                        };
                    };
                }    // namespace detail
            }        // namespace commitments

            namespace algorithms {
                namespace detail {
                    template <typename FRI>
                    using fri_field_element_consumer = ::nil::crypto3::zk::detail::field_element_consumer<
                        typename FRI::field_type,
                        typename FRI::merkle_tree_hash_type::word_type,
                        typename FRI::field_element_type
                    >;
                }    // namespace detail

                template<typename FRI,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m,
                                typename FRI::grinding_type
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
                                typename FRI::transcript_hash_type, FRI::m,
                                typename FRI::grinding_type
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
                                FRI::m, typename FRI::grinding_type
                            >,
                            FRI>::value,
                        bool>::type = true>
                static typename FRI::precommitment_type
                precommit(const math::polynomial_dfs<typename FRI::field_type::value_type> &f,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> D,
                          const std::size_t fri_step) {
                    if (f.size() != D->size()) {
                        throw std::runtime_error("Polynomial size does not match the domain size in FRI precommit.");
                    }
                    
                    std::size_t domain_size = D->size();
                    std::size_t coset_size = 1 << fri_step;
                    std::size_t leafs_number = domain_size / coset_size;
                    std::vector<detail::fri_field_element_consumer<FRI>> y_data(
                        leafs_number,
                        detail::fri_field_element_consumer<FRI>(coset_size)
                    );

                    for (std::size_t x_index = 0; x_index < leafs_number; x_index++) {
                        std::vector<std::array<std::size_t, FRI::m>> s_indices(coset_size / FRI::m);
                        s_indices[0][0] = x_index;
                        s_indices[0][1] = get_paired_index<FRI>(x_index, domain_size);

                        auto& element_consumer = y_data[x_index].reset_cursor();
                        element_consumer.consume(f[s_indices[0][0]]);
                        element_consumer.consume(f[s_indices[0][1]]);

                        std::size_t base_index = domain_size / (FRI::m * FRI::m);
                        std::size_t prev_half_size = 1;
                        std::size_t i = 1;
                        while (i < coset_size / FRI::m) {
                            for (std::size_t j = 0; j < prev_half_size; j++) {
                                s_indices[i][0] = (base_index + s_indices[j][0]) % domain_size;
                                s_indices[i][1] = get_paired_index<FRI>(s_indices[i][0], domain_size);

                                element_consumer.consume(f[s_indices[i][0]]);
                                element_consumer.consume(f[s_indices[i][1]]);

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
                                                FRI::m, typename FRI::grinding_type
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

                    if (f_dfs.size() != D->size()) {
                        f_dfs.resize(D->size(), nullptr, D);
                    }

                    return precommit<FRI>(f_dfs, D, fri_step);
                }

                template<typename FRI, typename ContainerType,
                        typename std::enable_if<
                                std::is_base_of<
                                        commitments::detail::basic_batched_fri<
                                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                                typename FRI::transcript_hash_type,
                                                FRI::m, typename FRI::grinding_type>,
                                        FRI>::value,
                                bool>::type = true>
                static typename std::enable_if<
                        (std::is_same<typename ContainerType::value_type, math::polynomial_dfs<typename FRI::field_type::value_type>>::value),
                        typename FRI::precommitment_type>::type
                precommit(ContainerType poly,
                          std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> D,
                          const std::size_t fri_step
                ) {
                    PROFILE_SCOPE("Basic FRI Precommit time");

                    // Resize uses low level thread pool, so we need to use the high level one here.
                    for (std::size_t i = 0; i < poly.size(); ++i) {
                        if (poly[i].size() != D->size()) {
                            poly[i].resize(D->size(), nullptr, D);
                        }
                    }

                    std::size_t domain_size = D->size();
                    std::size_t list_size = poly.size();
                    std::size_t coset_size = 1 << fri_step;
                    std::size_t leafs_number = domain_size / coset_size;
                    std::vector<detail::fri_field_element_consumer<FRI>> y_data(
                        leafs_number,
                        detail::fri_field_element_consumer<FRI>(coset_size * list_size)
                    );

                    for (std::size_t x_index = 0; x_index < leafs_number; x_index++) {
                        auto& element_consumer = y_data[x_index].reset_cursor();
                        for (std::size_t polynom_index = 0; polynom_index < list_size; polynom_index++) {
                            std::vector<std::array<std::size_t, FRI::m>> s_indices(coset_size / FRI::m);
                            s_indices[0][0] = x_index;
                            s_indices[0][1] = get_paired_index<FRI>(x_index, domain_size);

                            element_consumer.consume(poly[polynom_index][s_indices[0][0]]);
                            element_consumer.consume(poly[polynom_index][s_indices[0][1]]);

                            std::size_t base_index = domain_size / (FRI::m * FRI::m);
                            std::size_t prev_half_size = 1;
                            std::size_t i = 1;
                            while (i < coset_size / FRI::m) {
                                for (std::size_t j = 0; j < prev_half_size; j++) {
                                    s_indices[i][0] = (base_index + s_indices[j][0]) % domain_size;
                                    s_indices[i][1] = get_paired_index<FRI>(s_indices[i][0], domain_size);
                                    element_consumer.consume(poly[polynom_index][s_indices[i][0]]);
                                    element_consumer.consume(poly[polynom_index][s_indices[i][1]]);

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
                                                FRI::m, typename FRI::grinding_type>,
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
                calculate_s(const std::size_t x_index,
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

                template<typename FRI, typename PolynomialType>
                static std::tuple<
                    std::vector<PolynomialType>,
                    std::vector<typename FRI::precommitment_type>,
                    typename FRI::commitments_part_of_proof
                >
                commit_phase(
                    const PolynomialType& combined_Q,
                    const typename FRI::precommitment_type &combined_Q_precommitment,
                    const typename FRI::params_type &fri_params,
                    typename FRI::transcript_type &transcript)
                {
                    PROFILE_SCOPE("Basic FRI commit phase");
                    std::vector<PolynomialType> fs;
                    std::vector<typename FRI::precommitment_type> fri_trees;
                    typename FRI::commitments_part_of_proof commitments_proof;

                    auto f = combined_Q;
                    auto precommitment = combined_Q_precommitment;
                    std::size_t t = 0;

                    for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                        fs.push_back(f);
                        fri_trees.push_back(precommitment);
                        commitments_proof.fri_roots.push_back(commit<FRI>(precommitment));
                        transcript(commit<FRI>(precommitment));
                        for (std::size_t step_i = 0; step_i < fri_params.step_list[i]; ++step_i, ++t) {
                            typename FRI::field_type::value_type alpha = transcript.template challenge<typename FRI::field_type>();
                            // Calculate next f
                            if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                    PolynomialType>::value) {
                                f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alpha,
                                                                                                   fri_params.D[t]);
                            } else {
                                f = commitments::detail::fold_polynomial<typename FRI::field_type>(f, alpha);
                            }
                        }
                        if (i != fri_params.step_list.size() - 1) {
                            const auto& D = fri_params.D[t];
                            if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                    PolynomialType>::value) {
                                if (f.size() != D->size()) {
                                    f.resize(D->size(), nullptr, D);
                                }
                            }
                            precommitment = precommit<FRI>(f, D, fri_params.step_list[i + 1]);
                        }
                    }
                    fs.push_back(f);
                    if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>, PolynomialType>::value) {
                        commitments_proof.final_polynomial = math::polynomial<typename FRI::field_type::value_type>(f.coefficients());
                    } else {
                        commitments_proof.final_polynomial = f;
                    }

                    return std::make_tuple(fs, fri_trees, commitments_proof);
                }

                /** @brief Convert a set of polynomials from DFS form into coefficients form */
                template<typename FRI, typename PolynomialType>
                static std::map<
                    std::size_t,
                    std::vector<math::polynomial<typename FRI::field_type::value_type>>
                >  convert_polynomials_to_coefficients(
                    const typename FRI::params_type &fri_params,
                    const std::map<std::size_t, std::vector<PolynomialType>> &g)
                {
                    std::map<
                        std::size_t,
                        std::vector<math::polynomial<typename FRI::field_type::value_type>>
                    > g_coeffs;

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

                    return std::move(g_coeffs);
                }


                template<typename FRI, typename PolynomialType>
                static std::map<std::size_t, typename FRI::initial_proof_type>
                build_initial_proof(
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::params_type &fri_params,
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const std::map<
                        std::size_t,
                        std::vector<math::polynomial<typename FRI::field_type::value_type>>
                    > &g_coeffs,
                    std::uint64_t x_index)
                {
                    std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                    std::vector<std::array<std::size_t, FRI::m>> s_indices;
                    std::tie(s, s_indices) = calculate_s<FRI>(x_index, fri_params.step_list[0], fri_params.D[0]);

                    std::map<std::size_t, typename FRI::initial_proof_type> initial_proof;

                    for (const auto &it: g) {
                        auto k = it.first;
                        initial_proof[k] = {};
                        initial_proof[k].values.resize(it.second.size());
                        std::size_t coset_size = 1 << fri_params.step_list[0];
                        BOOST_ASSERT(coset_size / FRI::m == s.size());
                        BOOST_ASSERT(coset_size / FRI::m == s_indices.size());

                        // Fill values
                        const auto& g_k = it.second; // g[k]

                        for (std::size_t polynomial_index = 0; polynomial_index < g_k.size(); ++polynomial_index) {
                            initial_proof[k].values[polynomial_index].resize(coset_size / FRI::m);
                            if constexpr (std::is_same<
                                    math::polynomial_dfs<typename FRI::field_type::value_type>,
                                    PolynomialType>::value
                        ) {
                                if (g_k[polynomial_index].size() == fri_params.D[0]->size()) {
                                    for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                        std::size_t ind0 = std::min(s_indices[j][0], s_indices[j][1]);
                                        std::size_t ind1 = std::max(s_indices[j][0], s_indices[j][1]);
                                        initial_proof[k].values[polynomial_index][j][0] = g_k[polynomial_index][ind0];
                                        initial_proof[k].values[polynomial_index][j][1] = g_k[polynomial_index][ind1];
                                    }
                                } else {
                                    // Convert to coefficients form and evaluate. coset_size / FRI::m is usually just 1,
                                    // It makes no sense to resize in dfs form to then use just 2 values in 2 points.
                                    for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                        typename FRI::field_type::value_type s0;
                                        typename FRI::field_type::value_type s1;
                                        if( s_indices[j][0] < s_indices[j][1]){
                                            s0 = s[j][0];
                                            s1 = s[j][1];
                                        } else {
                                            s0 = s[j][1];
                                            s1 = s[j][0];
                                        }
                                        initial_proof[k].values[polynomial_index][j][0] = g_coeffs.at(k)[polynomial_index].evaluate(s0);
                                        initial_proof[k].values[polynomial_index][j][1] = g_coeffs.at(k)[polynomial_index].evaluate(s1);
                                    }
                                }
                            } else {
                                // Same for poly in coefficients form.
                                for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                    typename FRI::field_type::value_type s0;
                                    typename FRI::field_type::value_type s1;

                                    if( s_indices[j][0] < s_indices[j][1]){
                                        s0 = s[j][0];
                                        s1 = s[j][1];
                                    } else {
                                        s0 = s[j][1];
                                        s1 = s[j][0];
                                    }
                                    initial_proof[k].values[polynomial_index][j][0] = g_k[polynomial_index].evaluate(s0);
                                    initial_proof[k].values[polynomial_index][j][1] = g_k[polynomial_index].evaluate(s1);
                                }
                            }
                        }

                        // Fill merkle proofs
                        initial_proof[k].p = make_proof_specialized<FRI>(
                                get_folded_index<FRI>(x_index, fri_params.D[0]->size(), fri_params.step_list[0]),
                                fri_params.D[0]->size(), precommitments.at(k) );
                    }

                    return std::move(initial_proof);
                }

                template<typename FRI, typename PolynomialType>
                static std::vector<typename FRI::round_proof_type>
                build_round_proofs(
                    const typename FRI::params_type &fri_params,
                    const std::vector<typename FRI::precommitment_type> &fri_trees,
                    const std::vector<PolynomialType> &fs,
                    const math::polynomial<typename FRI::field_type::value_type> &final_polynomial,
                    std::uint64_t x_index)
                {
                    std::size_t domain_size = fri_params.D[0]->size();
                    std::size_t t = 0;
                    std::vector<typename FRI::round_proof_type> round_proofs(fri_params.step_list.size());

                    for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {

                        domain_size = fri_params.D[t]->size();
                        x_index %= domain_size;

                        round_proofs[i].p = make_proof_specialized<FRI>(
                                get_folded_index<FRI>(x_index, domain_size, fri_params.step_list[i]),
                                domain_size, fri_trees[i]);

                        t += fri_params.step_list[i];
                        if (i < fri_params.step_list.size() - 1) {
                            x_index %= fri_params.D[t]->size();

                            std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                            std::vector<std::array<std::size_t, FRI::m>> s_indices;
                            std::tie(s, s_indices) = calculate_s<FRI>(x_index, fri_params.step_list[i + 1], fri_params.D[t]);

                            std::size_t coset_size = 1 << fri_params.step_list[i + 1];
                            BOOST_ASSERT(coset_size / FRI::m == s.size());
                            BOOST_ASSERT(coset_size / FRI::m == s_indices.size());

                            round_proofs[i].y.resize(coset_size / FRI::m);
                            for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                if constexpr (std::is_same<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                        PolynomialType>::value) {
                                    std::size_t ind0 = std::min(s_indices[j][0], s_indices[j][1]);
                                    std::size_t ind1 = std::max(s_indices[j][0], s_indices[j][1]);
                                    round_proofs[i].y[j][0] = fs[i + 1][ind0];
                                    round_proofs[i].y[j][1] = fs[i + 1][ind1];
                                } else {
                                    typename FRI::field_type::value_type s0 = (s_indices[j][0] < s_indices[j][1] ? s[j][0] : s[j][1]);
                                    typename FRI::field_type::value_type s1 = (s_indices[j][0] > s_indices[j][1] ? s[j][0] : s[j][1]);
                                    round_proofs[i].y[j][0] = fs[i + 1].evaluate(s0);
                                    round_proofs[i].y[j][1] = fs[i + 1].evaluate(s1);
                                }
                            }
                        } else {
                            x_index %= fri_params.D[t - 1]->size();

                            typename FRI::field_type::value_type
                                x = fri_params.D[t - 1]->get_domain_element(x_index);
                            x *= x;

                            // Last step
                            // Assume that FRI rounds continues with step == 1
                            // x_index % (domain_size / 2) -- index in the next round
                            // fri_params.D[t-1]->size()/4 -- half of the next domain size
                            // Then next round values will be written in the straight order if next round index < next domain size - 1
                            // Otherwise, they will be written in the reverse order.

                            std::size_t ind = (x_index %(fri_params.D[t-1]->size()/2) < fri_params.D[t-1]->size()/4)? 0: 1;
                            round_proofs[i].y.resize(1);
                            round_proofs[i].y[0][ind] = final_polynomial.evaluate(x);
                            round_proofs[i].y[0][1-ind] = final_polynomial.evaluate(-x);
                        }
                    }
                    return std::move(round_proofs);
                }


                template<typename FRI, typename PolynomialType>
                static typename FRI::round_proofs_batch_type query_phase_round_proofs(
                    const typename FRI::params_type &fri_params,
                    const std::vector<typename FRI::precommitment_type> &fri_trees,
                    const std::vector<PolynomialType> &fs,
                    const math::polynomial<typename FRI::field_type::value_type> &final_polynomial,
                    const std::vector<typename FRI::field_type::value_type>& challenges)
                {
                    typename FRI::round_proofs_batch_type proof;

                    for (std::size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                        std::size_t domain_size = fri_params.D[0]->size();
                        typename FRI::field_type::value_type x = challenges[query_id];
                        x = x.pow((FRI::field_type::modulus - 1) / domain_size);

                        std::uint64_t x_index = 0;

                        while (fri_params.D[0]->get_domain_element(x_index) != x) {
                            ++x_index;
                        }

                        // Fill round proofs
                        std::vector<typename FRI::round_proof_type> round_proofs =
                            build_round_proofs<FRI, PolynomialType>(
                                fri_params, fri_trees, fs, final_polynomial, x_index);

                        proof.round_proofs.emplace_back(std::move(round_proofs));
                    }
                    return proof;
                }

                template<typename FRI, typename PolynomialType>
                static typename FRI::initial_proofs_batch_type query_phase_initial_proofs(
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::params_type &fri_params,
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const std::vector<typename FRI::field_type::value_type>& challenges)
                {
                    typename FRI::initial_proofs_batch_type proof;

                    // If we have DFS polynomials, and we are going to resize them, better convert them to coefficients form,
                    // and compute their values in those 2 * FRI::lambda points each, which is normally 2 * 20.
                    // In case lambda becomes much larger than log(2, average polynomial size), then this will not be optimal.
                    // For lambda = 20 and 2^20 rows in assignment table, it's faster and uses less RAM.
                    std::map<std::size_t, std::vector<math::polynomial<typename FRI::field_type::value_type>>> g_coeffs =
                        convert_polynomials_to_coefficients<FRI, PolynomialType>(fri_params, g);

                    for (std::size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                        std::size_t domain_size = fri_params.D[0]->size();
                        typename FRI::field_type::value_type x = challenges[query_id];
                        x = x.pow((FRI::field_type::modulus - 1) / domain_size);

                        std::uint64_t x_index = 0;

                        while (fri_params.D[0]->get_domain_element(x_index) != x) {
                            ++x_index;
                        }

                        std::map<std::size_t, typename FRI::initial_proof_type>
                            initial_proof = build_initial_proof<FRI, PolynomialType>(
                                    precommitments,
                                    fri_params, g, g_coeffs, x_index);

                        proof.initial_proofs.emplace_back(std::move(initial_proof));
                    }
                    return proof;
                }

                template<typename FRI, typename PolynomialType>
                static std::vector<typename FRI::query_proof_type>
                query_phase_with_challenges(
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::params_type &fri_params,
                    const std::vector<typename FRI::field_type::value_type>& challenges,
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const std::vector<typename FRI::precommitment_type> &fri_trees,
                    const std::vector<PolynomialType> &fs,
                    const math::polynomial<typename FRI::field_type::value_type> &final_polynomial)
                {
                    typename FRI::initial_proofs_batch_type initial_proofs = 
                        query_phase_initial_proofs<FRI, PolynomialType>(
                            precommitments, fri_params, g, challenges);
                        
                    typename FRI::round_proofs_batch_type round_proofs = 
                        query_phase_round_proofs<FRI, PolynomialType>(
                            fri_params, fri_trees, fs, final_polynomial, challenges);

                    // Join intial proofs and round proofs into a structure of query proofs.
                    std::vector<typename FRI::query_proof_type> query_proofs(fri_params.lambda);

                    for (std::size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                        query_proofs[query_id] = {std::move(initial_proofs.initial_proofs[query_id]), 
                                                  std::move(round_proofs.round_proofs[query_id])};
                    }
                    return query_proofs;
                }

                template<typename FRI, typename PolynomialType>
                static std::vector<typename FRI::query_proof_type>
                query_phase(
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::params_type &fri_params,
                    typename FRI::transcript_type &transcript,
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const std::vector<typename FRI::precommitment_type> &fri_trees,
                    const std::vector<PolynomialType> &fs,
                    const math::polynomial<typename FRI::field_type::value_type> &final_polynomial)
                {
                    PROFILE_SCOPE("Basic FRI query phase");
                    std::vector<typename FRI::field_type::value_type> challenges =
                        transcript.template challenges<typename FRI::field_type>(fri_params.lambda);

                    return query_phase_with_challenges<FRI, PolynomialType>(
                        precommitments, fri_params, challenges, g, fri_trees, fs, final_polynomial);
                }


                template<typename FRI, typename PolynomialType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type,
                                FRI::m, typename FRI::grinding_type>,
                            FRI>::value,
                        bool>::type = true>
                static typename FRI::proof_type proof_eval(
                    const std::map<std::size_t, std::vector<PolynomialType>> &g,
                    const PolynomialType& combined_Q,
                    const std::map<std::size_t, typename FRI::precommitment_type> &precommitments,
                    const typename FRI::precommitment_type &combined_Q_precommitment,
                    const typename FRI::params_type &fri_params,
                    typename FRI::transcript_type &transcript
                ) {
                    PROFILE_SCOPE("Basic FRI proof_eval time");
                    typename FRI::proof_type proof;

                    BOOST_ASSERT(check_step_list<FRI>(fri_params));
                    // TODO: add necessary checks
                    //BOOST_ASSERT(check_initial_precommitment<FRI>(precommitments, fri_params));

                    // Commit phase

                    std::vector<typename FRI::precommitment_type> fri_trees;
                    std::vector<PolynomialType> fs;
                    math::polynomial<typename FRI::field_type::value_type> final_polynomial; 

                    // Contains fri_roots and final_polynomial.
                    typename FRI::commitments_part_of_proof commitments_proof; 

                    std::tie(fs, fri_trees, commitments_proof) =
                        commit_phase<FRI, PolynomialType>(
                            combined_Q,
                            combined_Q_precommitment,
                            fri_params, transcript);

                    // Grinding
                    if (fri_params.use_grinding) {
                        PROFILE_SCOPE("Basic FRI grinding phase");
                        proof.proof_of_work = FRI::grinding_type::generate(transcript, fri_params.grinding_parameter);
                    }

                    // Query phase
                    proof.query_proofs = query_phase<FRI, PolynomialType>(
                        precommitments, fri_params, transcript,
                        g, fri_trees, fs, commitments_proof.final_polynomial);

                    proof.fri_roots = std::move(commitments_proof.fri_roots);
                    proof.final_polynomial = std::move(commitments_proof.final_polynomial);

                    return proof;
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

                    if (fri_params.use_grinding && !FRI::grinding_type::verify(
                            transcript, proof.proof_of_work, fri_params.grinding_parameter)){
                        return false;
                    }
                    for (std::size_t query_id = 0; query_id < fri_params.lambda; query_id++) {
                        const typename FRI::query_proof_type &query_proof = proof.query_proofs[query_id];

                        std::size_t domain_size = fri_params.D[0]->size();
                        std::size_t coset_size = 1 << fri_params.step_list[0];
                        typename FRI::field_type::value_type x_challenge = transcript.template challenge<typename FRI::field_type>();
                        typename FRI::field_type::value_type x = x_challenge.pow((FRI::field_type::modulus - 1)/domain_size);
                        std::uint64_t x_index = 0;
                        for( x_index = 0; x_index < domain_size; x_index++ ){
                            if( fri_params.D[0]->get_domain_element(x_index) == x ){
                                break;
                            }
                        }

                        std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                        std::vector<std::array<std::size_t, FRI::m>> s_indices;
                        std::tie(s, s_indices) = calculate_s<FRI>(x_index, fri_params.step_list[0], fri_params.D[0]);
                        auto correct_order_idx = get_correct_order<FRI>(x_index, domain_size, fri_params.step_list[0],
                                                                        s_indices);

                        // Check initial proof.
                        for( auto const &it: query_proof.initial_proof ){
                            auto k = it.first;
                            if (query_proof.initial_proof.at(k).p.root() != commitments.at(k) ) {
                                return false;
                            }

                            detail::fri_field_element_consumer<FRI> leaf_data(
                                coset_size * query_proof.initial_proof.at(k).values.size());

                            for (std::size_t i = 0; i < query_proof.initial_proof.at(k).values.size(); i++) {
                                for (auto [idx, pair_idx] : correct_order_idx) {
                                    leaf_data.consume(query_proof.initial_proof.at(k).values[i][idx][0]);
                                    leaf_data.consume(query_proof.initial_proof.at(k).values[i][idx][1]);
                                }
                            }
                            if (!query_proof.initial_proof.at(k).p.validate(leaf_data)) {
                                BOOST_LOG_TRIVIAL(info) << "Wrong initial proof";
                                return false;
                            }
                        }

                        // Calculate combinedQ values
                        typename FRI::field_type::value_type theta_acc = FRI::field_type::value_type::one();
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
                                std::size_t id0 = s_indices[j][0] < s_indices[j][1] ? 0 : 1;
                                std::size_t id1 = s_indices[j][0] < s_indices[j][1] ? 1 : 0;
                                Q[j][0] -= combined_U[p];
                                Q[j][1] -= combined_U[p];
                                Q[j][0] *= denominators[p].evaluate(s[j][id0]).inversed();
                                Q[j][1] *= denominators[p].evaluate(s[j][id1]).inversed();
                                y[j][0] += Q[j][0];
                                y[j][1] += Q[j][1];
                            }
                        }
                        // Check round proofs
                        std::size_t t = 0;
                        typename FRI::polynomial_values_type y_next;
                        for (std::size_t i = 0; i < fri_params.step_list.size(); i++) {
                            coset_size = 1 << fri_params.step_list[i];
                            if (query_proof.round_proofs[i].p.root() != proof.fri_roots[i])
                                return false;

                            std::tie(s, s_indices) = calculate_s<FRI>(x_index, fri_params.step_list[i],
                                                                      fri_params.D[t]);
                            detail::fri_field_element_consumer<FRI> leaf_data(coset_size);
                            auto correct_order_idx =
                                    get_correct_order<FRI>(x_index, domain_size, fri_params.step_list[i], s_indices);
                            for (auto [idx, pair_idx]: correct_order_idx) {
                                leaf_data.consume(y[idx][0]);
                                leaf_data.consume(y[idx][1]);
                            }
                            if (!query_proof.round_proofs[i].p.validate(leaf_data)) {
                                BOOST_LOG_TRIVIAL(info) << "Wrong round merkle proof on " << i << "-th round";
                                return false;
                            }

                            // colinear check
                            for (std::size_t step_i = 0; step_i < fri_params.step_list[i] - 1; step_i++, t++) {
                                y_next.resize(y.size() / FRI::m);

                                domain_size = fri_params.D[t]->size();
                                x_index %= domain_size;
                                x = fri_params.D[t]->get_domain_element(x_index);

                                auto [s_next, s_indices_next] = calculate_s<FRI>(
                                    x_index % fri_params.D[t+1]->size(),
                                    fri_params.step_list[i], fri_params.D[t+1]
                                );

                                std::tie(s, s_indices) = calculate_s<FRI>(
                                    x_index, fri_params.step_list[i], fri_params.D[t]);

                                std::size_t new_domain_size = domain_size;
                                for (std::size_t y_ind = 0; y_ind < y_next.size(); y_ind++) {
                                    std::size_t ind0 = s_indices[2 * y_ind][0] < s_indices[2 * y_ind][1] ? 0 : 1;
                                    auto s_ch = s[2*y_ind][ind0];

                                    std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points_l{
                                        std::make_pair(s_ch, y[2 * y_ind][0]),
                                        std::make_pair(-s_ch, y[2 * y_ind][1]),
                                    };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_l =
                                            math::lagrange_interpolation(interpolation_points_l);

                                    ind0 = s_indices[2 * y_ind + 1][0] < s_indices[2 * y_ind + 1][1] ? 0 : 1;
                                    s_ch = s[2*y_ind + 1][ind0];
                                    std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points_r{
                                        std::make_pair(s_ch, y[2 * y_ind + 1][0]),
                                        std::make_pair(-s_ch, y[2 * y_ind + 1][1]),
                                    };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_r =
                                            math::lagrange_interpolation(interpolation_points_r);

                                    new_domain_size /= FRI::m;

                                    std::size_t interpolant_index_l = s_indices_next[y_ind][0];
                                    std::size_t interpolant_index_r = s_indices_next[y_ind][1];

                                    if( interpolant_index_l < interpolant_index_r){
                                        y_next[y_ind][0] = interpolant_l.evaluate(alphas[t]);
                                        y_next[y_ind][1] = interpolant_r.evaluate(alphas[t]);
                                    } else {
                                        y_next[y_ind][0] = interpolant_r.evaluate(alphas[t]);
                                        y_next[y_ind][1] = interpolant_l.evaluate(alphas[t]);
                                    }
                                }
                                x = x * x;
                                y = y_next;
                            }
                            domain_size = fri_params.D[t]->size();
                            x_index %= domain_size;
                            x = fri_params.D[t]->get_domain_element(x_index);
                            std::tie(s, s_indices) = calculate_s<FRI>(
                                x_index, fri_params.step_list[i],
                                fri_params.D[t]);

                            std::size_t ind0 = s_indices[0][0] < s_indices[0][1] ? 0 : 1;
                            auto s_ch = s[0][ind0];
                            std::vector<std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>> interpolation_points{
                                std::make_pair(s_ch, y[0][0]),
                                std::make_pair(-s_ch, y[0][1]),
                            };
                            math::polynomial<typename FRI::field_type::value_type> interpolant_poly =
                                    math::lagrange_interpolation(interpolation_points);
                            auto interpolant = interpolant_poly.evaluate(alphas[t]);

                            std::size_t ind = s_indices[0][ind0] % (fri_params.D[t]->size()/2) < fri_params.D[t]->size() / 4 ? 0 : 1;
                            if (interpolant != query_proof.round_proofs[i].y[0][ind]) {
                                return false;
                            }

                            // For the last round we check final polynomial nor colinear_check
                            y = query_proof.round_proofs[i].y;
                            if (i < fri_params.step_list.size() - 1) {
                                t++;
                                domain_size = fri_params.D[t]->size();
                                x_index %= domain_size;
                                x = fri_params.D[t]->get_domain_element(x_index);
                            }
                        }

                        // Final polynomial check
                        x_index %= fri_params.D[t]->size();
                        x = fri_params.D[t]->get_domain_element(x_index);
                        x = x * x;
                        std::size_t ind = x_index % (fri_params.D[t]->size() / 2) < fri_params.D[t]->size() / 4 ? 0 : 1;
                        if (y[0][ind] != proof.final_polynomial.evaluate(x)) {
                            return false;
                        }
                        if (y[0][1-ind] != proof.final_polynomial.evaluate(-x)) {
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
