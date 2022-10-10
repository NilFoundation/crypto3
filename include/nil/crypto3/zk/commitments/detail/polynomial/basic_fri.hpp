//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2021-2022 Aleksei Moskvin <alalmoskvin@nil.foundation>
// Copyright (c) 2022 Ilias Khairullin <ilias@nil.foundation>
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
                             std::size_t M, std::size_t BatchSize, bool IsConstSize>
                    struct basic_batched_fri {
                        BOOST_STATIC_ASSERT_MSG(M == 2, "unsupported m value!");

                        constexpr static const std::size_t m = M;
                        constexpr static const std::size_t leaf_size = BatchSize;
                        constexpr static const bool is_const_size = IsConstSize;

                        typedef FieldType field_type;
                        typedef MerkleTreeHashType merkle_tree_hash_type;
                        typedef TranscriptHashType transcript_hash_type;

                        typedef std::array<typename field_type::value_type, m> polynomial_value_type;
                        typedef std::vector<polynomial_value_type> polynomial_values_type;
                        typedef typename select_container<is_const_size, polynomial_values_type, leaf_size>::type
                            polynomials_values_type;
                        typedef std::vector<polynomials_values_type> rounds_polynomials_values_type;

                        typedef typename containers::merkle_tree<MerkleTreeHashType, 2> merkle_tree_type;
                        typedef typename containers::merkle_proof<MerkleTreeHashType, 2> merkle_proof_type;

                        using Endianness = nil::marshalling::option::big_endian;
                        using field_element_type =
                            nil::crypto3::marshalling::types::field_element<nil::marshalling::field_type<Endianness>,
                                                                            typename FieldType::value_type>;

                        using precommitment_type = merkle_tree_type;
                        using commitment_type = typename precommitment_type::value_type;
                        using transcript_type = transcript::fiat_shamir_heuristic_sequential<TranscriptHashType>;

                        struct params_type {
                            bool operator==(const params_type &rhs) const {
                                return r == rhs.r && max_degree == rhs.max_degree && D == rhs.D;
                            }
                            bool operator!=(const params_type &rhs) const {
                                return !(rhs == *this);
                            }

                            // TODO: Better if we can construct params_type from any batch size to another
                            params_type(
                                const typename basic_batched_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M,
                                                                 1, false>::params_type &obj) {
                                r = obj.r;
                                max_degree = obj.max_degree;
                                D = obj.D;
                                step_list = obj.step_list;
                            }

                            params_type(
                                const typename basic_batched_fri<FieldType, MerkleTreeHashType, TranscriptHashType, M,
                                                                 1, true>::params_type &obj) {
                                r = obj.r;
                                max_degree = obj.max_degree;
                                D = obj.D;
                                step_list = obj.step_list;
                            }

                            params_type() {};

                            std::size_t r;
                            std::size_t max_degree;
                            std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D;
                            std::vector<std::size_t> step_list;
                        };

                        struct round_proof_type {
                            bool operator==(const round_proof_type &rhs) const {
                                return p == rhs.p && T_root == rhs.T_root && colinear_path == rhs.colinear_path;
                            }

                            bool operator!=(const round_proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            //                          y and colinear value are stored in proof_type::values;
                            //                          for i-th round y = proof_type::values[i]; colinear_value =
                            //                          proof_type::values[i+1];

                            merkle_proof_type p;    // for y
                            typename merkle_tree_type::value_type T_root;
                            merkle_proof_type colinear_path;    // for colinear_value
                        };

                        struct proof_type {
                            bool operator==(const proof_type &rhs) const {
                                return values == rhs.values && round_proofs == rhs.round_proofs && final_polynomials == rhs.final_polynomials;
                            }

                            bool operator!=(const proof_type &rhs) const {
                                return !(rhs == *this);
                            }

                            /* Returns y for i-th round*/
                            polynomials_values_type &get_y(int i) {
                                return this->values[i];
                            }

                            /* Returns colinear_values for i-th round*/
                            polynomials_values_type &get_colinear_value(int i) {
                                return this->values[i + 1];
                            }

                            typedef typename select_container<is_const_size,
                                                              math::polynomial<typename FieldType::value_type>,
                                                              leaf_size>::type final_polynomials_type;

                            std::vector<round_proof_type> round_proofs;    // 0..r-2
                            final_polynomials_type final_polynomials;

                            rounds_polynomials_values_type values;    // y-s and colinear_values for round_proof_type
                        };
                    };
                }    // namespace detail
            }        // namespace commitments

            namespace algorithms {
                template<typename FRI,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::detail::basic_batched_fri<
                                     typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                                 FRI>::value,
                             bool>::type = true>
                static typename FRI::commitment_type commit(const typename FRI::precommitment_type &P) {
                    return P.root();
                }

                template<typename FRI, std::size_t list_size,
                         typename std::enable_if<
                             std::is_base_of<
                                 commitments::detail::basic_batched_fri<
                                     typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
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
                                     typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                                 FRI>::value,
                             bool>::type = true>
                static typename FRI::precommitment_type
                    precommit(math::polynomial_dfs<typename FRI::field_type::value_type> &f,
                              std::shared_ptr<math::evaluation_domain<typename FRI::field_type>>
                                  D,
                              const std::size_t fri_step) {

                    if (f.size() != D->size()) {
                        f.resize(D->size());
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
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                                 FRI>::value,
                             bool>::type = true>
                static typename FRI::precommitment_type
                    precommit(const math::polynomial<typename FRI::field_type::value_type> &f,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D,
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
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                                 FRI>::value,
                             bool>::type = true>
                static typename std::enable_if<
                    (std::is_same<typename ContainerType::value_type,
                                  math::polynomial_dfs<typename FRI::field_type::value_type>>::value),
                    typename FRI::precommitment_type>::type
                    precommit(ContainerType poly,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D,
                              const std::size_t fri_step) {

#ifdef ZK_PLACEHOLDER_PROFILING_ENABLED
                    auto begin = std::chrono::high_resolution_clock::now();
                    auto last = begin;
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::high_resolution_clock::now() - last);
#endif
                    for (int i = 0; i < poly.size(); ++i) {
                        // BOOST_ASSERT (poly[i].size() == D->size());
                        if (poly[i].size() != D->size()) {
                            poly[i].resize(D->size());
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
                                     typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                                 FRI>::value,
                             bool>::type = true>
                static typename std::enable_if<
                    (std::is_same<typename ContainerType::value_type,
                                  math::polynomial<typename FRI::field_type::value_type>>::value),
                    typename FRI::precommitment_type>::type
                    precommit(const ContainerType &poly,
                              const std::shared_ptr<math::evaluation_domain<typename FRI::field_type>> &D,
                              const std::size_t fri_step) {

                    std::size_t list_size = poly.size();
                    std::vector<math::polynomial_dfs<typename FRI::field_type::value_type>> poly_dfs(list_size);
                    for (std::size_t i = 0; i < list_size; i++) {
                        poly_dfs[i].from_coefficients(poly[i]);
                        poly_dfs[i].resize(D->size());
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

                template<typename FRI>
                bool check_initial_precommitment(const typename FRI::precommitment_type &T,
                                                 const typename FRI::params_type &fri_params) {
                    std::size_t domain_size = fri_params.D[0]->size();
                    std::size_t coset_size = 1 << fri_params.step_list[0];
                    std::size_t leafs_number = domain_size / coset_size;
                    return leafs_number == T.leaves();
                }

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

                    return std::move(std::make_pair(std::move(s), std::move(s_indices)));
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
                        auto found_it =
                            std::find_if(std::cbegin(input_s_indices), std::cend(input_s_indices), [&](const auto &v) {
                                if (v[0] == correctly_ordered_s_indices[i] &&
                                    v[1] == get_paired_index<FRI>(correctly_ordered_s_indices[i], domain_size)) {
                                    correct_order_idx[i].second = 0;
                                    return true;
                                } else if (v[1] == correctly_ordered_s_indices[i] &&
                                           v[0] == get_paired_index<FRI>(correctly_ordered_s_indices[i], domain_size)) {
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

                template<
                    typename FRI, typename ContainerType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                            FRI>::value &&
                            (!std::is_same_v<typename ContainerType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(ContainerType f,
                               ContainerType g,
                               const typename FRI::precommitment_type &T,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    BOOST_ASSERT(check_step_list<FRI>(fri_params));
                    BOOST_ASSERT(check_initial_precommitment<FRI>(T, fri_params));

                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 typename ContainerType::value_type>) {
                        for (int i = 0; i < f.size(); ++i) {
                            // BOOST_ASSERT(g[i].size() == fri_params.D[0]->size());
                            if (f[i].size() != fri_params.D[0]->size()) {
                                f[i].resize(fri_params.D[0]->size());
                            }
                            if (g[i].size() != fri_params.D[0]->size()) {
                                g[i].resize(fri_params.D[0]->size());
                            }
                        }
                    }

                    BOOST_ASSERT(f.size() == g.size());
                    std::size_t leaf_size = f.size();

                    transcript(commit<FRI>(T));

                    // TODO: how to sample x?
                    std::size_t domain_size = fri_params.D[0]->size();
                    std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                    typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);

                    std::vector<typename FRI::round_proof_type> round_proofs;
                    std::unique_ptr<typename FRI::merkle_tree_type> p_tree =
                        std::make_unique<typename FRI::merkle_tree_type>(T);
                    typename FRI::merkle_tree_type T_next;

                    std::size_t basis_index = 0;
                    std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                    std::vector<std::array<std::size_t, FRI::m>> s_indices;

                    typename FRI::rounds_polynomials_values_type values;

                    for (std::size_t i = 0; i < fri_params.step_list.size() - 1; i++) {
                        domain_size = fri_params.D[basis_index]->size();
                        x_index %= domain_size;

                        // m = 2, so:
                        if constexpr (FRI::m == 2) {
                            std::tie(s, s_indices) =
                                calculate_s<FRI>(x, x_index, fri_params.step_list[i], fri_params.D[basis_index]);
                        } else {
                            return {};
                        }

                        typename FRI::polynomials_values_type y;
                        if constexpr (!FRI::is_const_size) {
                            y.resize(leaf_size);
                        }

                        std::size_t coset_size = 1 << fri_params.step_list[i];
                        BOOST_ASSERT(coset_size / FRI::m == s.size());
                        BOOST_ASSERT(coset_size / FRI::m == s_indices.size());
                        if (basis_index == 0) {
                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                y[polynom_index].resize(coset_size / FRI::m);
                                for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                    if constexpr (std::is_same_v<
                                                      math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                      typename ContainerType::value_type>) {
                                        y[polynom_index][j][0] = g[polynom_index][s_indices[j][0]];
                                        y[polynom_index][j][1] = g[polynom_index][s_indices[j][1]];
                                    } else {
                                        y[polynom_index][j][0] = g[polynom_index].evaluate(s[j][0]);
                                        y[polynom_index][j][1] = g[polynom_index].evaluate(s[j][1]);
                                    }
                                }
                            }
                            values.push_back(y);    // y for first round
                        }

                        // TODO: check if leaf index calculation is correct
                        auto p = make_proof_specialized<FRI>(
                            get_folded_index<FRI>(x_index, domain_size, fri_params.step_list[i]), domain_size, *p_tree);

                        typename FRI::polynomials_values_type colinear_value;
                        if constexpr (!FRI::is_const_size) {
                            colinear_value.resize(leaf_size);
                        }

                        for (std::size_t step_i = 0; step_i < fri_params.step_list[i]; step_i++, basis_index++) {
                            typename FRI::field_type::value_type alpha =
                                transcript.template challenge<typename FRI::field_type>();

                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                             typename ContainerType::value_type>) {
                                    if (basis_index == 0) {
                                        f[polynom_index].resize(fri_params.D[basis_index]->size());
                                    }
                                    f[polynom_index] = commitments::detail::fold_polynomial<typename FRI::field_type>(
                                        f[polynom_index], alpha, fri_params.D[basis_index]);
                                } else {
                                    f[polynom_index] = commitments::detail::fold_polynomial<typename FRI::field_type>(
                                        f[polynom_index], alpha);
                                }
                            }

                            x_index = x_index % (fri_params.D[basis_index + 1]->size());
                            x = fri_params.D[basis_index + 1]->get_domain_element(x_index);
                        }

                        std::tie(s, s_indices) =
                            calculate_s<FRI>(x, x_index, fri_params.step_list[i + 1], fri_params.D[basis_index]);
                        coset_size = 1 << fri_params.step_list[i + 1];
                        BOOST_ASSERT(coset_size / FRI::m == s.size());
                        BOOST_ASSERT(coset_size / FRI::m == s_indices.size());
                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            colinear_value[polynom_index].resize(coset_size / FRI::m);
                            for (std::size_t j = 0; j < coset_size / FRI::m; j++) {
                                if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                             typename ContainerType::value_type>) {
                                    colinear_value[polynom_index][j][0] = f[polynom_index][s_indices[j][0]];
                                    colinear_value[polynom_index][j][1] = f[polynom_index][s_indices[j][1]];
                                } else {
                                    colinear_value[polynom_index][j][0] = f[polynom_index].evaluate(s[j][0]);
                                    colinear_value[polynom_index][j][1] = f[polynom_index].evaluate(s[j][1]);
                                }
                            }
                        }
                        values.push_back(colinear_value);    // colinear_value for this iteration and y for the next.

                        T_next = precommit<FRI>(f, fri_params.D[basis_index],
                                                fri_params.step_list[i + 1]);    // new merkle tree
                        transcript(commit<FRI>(T_next));

                        typename FRI::merkle_proof_type colinear_path = make_proof_specialized<FRI>(
                            get_folded_index<FRI>(x_index, fri_params.D[basis_index]->size(),
                                                  fri_params.step_list[i + 1]),
                            fri_params.D[basis_index]->size(), T_next);

                        round_proofs.push_back(typename FRI::round_proof_type({p, p_tree->root(), colinear_path}));

                        p_tree = std::make_unique<typename FRI::merkle_tree_type>(T_next);
                    }

                    typename FRI::proof_type::final_polynomials_type final_polynomials;

                    if constexpr (!FRI::is_const_size) {
                        final_polynomials.resize(f.size());
                    }
                    if constexpr (std::is_same_v<math::polynomial_dfs<typename FRI::field_type::value_type>,
                                                 typename ContainerType::value_type>) {
                        for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                            final_polynomials[polynom_index] =
                                math::polynomial<typename FRI::field_type::value_type>(f[polynom_index].coefficients());
                        }
                    } else {
                        for (std::size_t polynom_index = 0; polynom_index < f.size(); polynom_index++) {
                            final_polynomials[polynom_index] = f[polynom_index];
                        }
                    }
                    return typename FRI::proof_type({round_proofs, final_polynomials, values});
                }

                template<
                    typename FRI, typename PolynomType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                            FRI>::value &&
                            (std::is_same_v<typename PolynomType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(PolynomType f,
                               const PolynomType &g,
                               const typename FRI::precommitment_type &T,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    std::array<PolynomType, 1> f_new = {f};
                    std::array<PolynomType, 1> g_new = {g};

                    return proof_eval<FRI>(f_new, g_new, T, fri_params, transcript);
                }

                template<
                    typename FRI, typename ContainerType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                            FRI>::value &&
                            (!std::is_same_v<typename ContainerType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(ContainerType f,
                               ContainerType g,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    // TODO: f or g should be commited first
                    typename FRI::precommitment_type T = precommit<FRI>(g, fri_params.D[0], fri_params.step_list[0]);

                    return proof_eval<FRI>(f, g, T, fri_params, transcript);
                }

                template<
                    typename FRI, typename PolynomType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                            FRI>::value &&
                            (std::is_same_v<typename PolynomType::value_type, typename FRI::field_type::value_type>),
                        bool>::type = true>
                static typename FRI::proof_type
                    proof_eval(PolynomType f,
                               const PolynomType &g,
                               const typename FRI::params_type &fri_params,
                               typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    std::array<PolynomType, 1> f_new = {f};
                    std::array<PolynomType, 1> g_new = {g};

                    // TODO: f or g should be commited first
                    typename FRI::precommitment_type T =
                        precommit<FRI>(g_new, fri_params.D[0], fri_params.step_list[0]);

                    return proof_eval<FRI>(f_new, g_new, fri_params, transcript);
                }

                template<
                    typename FRI, typename ContainerType,
                    typename std::enable_if<
                        std::is_base_of<
                            commitments::detail::basic_batched_fri<
                                typename FRI::field_type, typename FRI::merkle_tree_hash_type,
                                typename FRI::transcript_hash_type, FRI::m, FRI::leaf_size, FRI::is_const_size>,
                            FRI>::value &&
                            !std::is_same_v<typename ContainerType::value_type, typename FRI::field_type::value_type>,
                        bool>::type = true>
                static bool verify_eval(typename FRI::proof_type &proof,
                                        typename FRI::params_type &fri_params,
                                        const typename FRI::commitment_type &t_polynomials,
                                        const ContainerType &U,
                                        const ContainerType &V,
                                        typename FRI::transcript_type &transcript = typename FRI::transcript_type()) {
                    BOOST_ASSERT(check_step_list<FRI>(fri_params));
                    BOOST_ASSERT(U.size() == V.size());

                    std::size_t leaf_size;
                    if constexpr (!FRI::is_const_size) {
                        leaf_size = proof.final_polynomials.size();
                    } else {
                        leaf_size = FRI::leaf_size;
                    }

                    transcript(t_polynomials);

                    std::size_t domain_size = fri_params.D[0]->size();
                    std::uint64_t x_index = (transcript.template int_challenge<std::uint64_t>()) % domain_size;
                    typename FRI::field_type::value_type x = fri_params.D[0]->get_domain_element(x_index);
                    std::uint64_t x_index_next;
                    typename FRI::field_type::value_type x_next;

                    std::size_t r = fri_params.r;

                    std::vector<std::array<typename FRI::field_type::value_type, FRI::m>> s;
                    std::vector<std::array<std::size_t, FRI::m>> s_indices;

                    if constexpr (FRI::m == 2) {
                        std::tie(s, s_indices) = calculate_s<FRI>(x, x_index, fri_params.step_list[0], fri_params.D[0]);
                    } else {
                        return false;
                    }

                    typename FRI::polynomials_values_type y_0;
                    if constexpr (!FRI::is_const_size) {
                        y_0.resize(leaf_size);
                    }

                    if (U.size() == 1) {
                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            y_0[polynom_index].resize(proof.get_y(0)[polynom_index].size());
                            for (std::size_t y_i = 0; y_i < y_0[polynom_index].size(); y_i++) {
                                for (std::size_t j = 0; j < FRI::m; j++) {
                                    y_0[polynom_index][y_i][j] =
                                        (proof.get_y(0)[polynom_index][y_i][j] - U[0].evaluate(s[y_i][j])) /
                                        V[0].evaluate(s[y_i][j]);
                                }
                            }
                        }
                    } else {
                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            y_0[polynom_index].resize(proof.get_y(0)[polynom_index].size());
                            for (std::size_t y_i = 0; y_i < y_0[polynom_index].size(); y_i++) {
                                for (std::size_t j = 0; j < FRI::m; j++) {
                                    y_0[polynom_index][y_i][j] =
                                        (proof.get_y(0)[polynom_index][y_i][j] - U[polynom_index].evaluate(s[y_i][j])) /
                                        V[polynom_index].evaluate(s[y_i][j]);
                                }
                            }
                        }
                    }

                    std::size_t basis_index = 0;
                    for (std::size_t i = 0; i < fri_params.step_list.size() - 1; i++) {
                        domain_size = fri_params.D[basis_index]->size();
                        x_index %= domain_size;

                        // m = 2, so:
                        if constexpr (FRI::m == 2) {
                            std::tie(s, s_indices) =
                                calculate_s<FRI>(x, x_index, fri_params.step_list[i], fri_params.D[basis_index]);
                        } else {
                            return false;
                        }

                        {
                            const std::size_t coset_size = 1 << fri_params.step_list[i];
                            auto correct_order_idx =
                                get_correct_order<FRI>(x_index, domain_size, fri_params.step_list[i], s_indices);
                            std::vector<std::uint8_t> leaf_data(coset_size * FRI::field_element_type::length() *
                                                                leaf_size);
                            auto write_iter = leaf_data.begin();
                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                for (auto [idx, pair_idx] : correct_order_idx) {
                                    typename FRI::field_element_type leaf_val0(
                                        proof.get_y(i)[polynom_index][idx][pair_idx]);
                                    leaf_val0.write(write_iter, FRI::field_element_type::length());
                                    typename FRI::field_element_type leaf_val1(
                                        proof.get_y(i)[polynom_index][idx][(pair_idx + 1) % FRI::m]);
                                    leaf_val1.write(write_iter, FRI::field_element_type::length());
                                }
                            }
                            if (!proof.round_proofs[i].p.validate(leaf_data)) {
                                return false;
                            }

                            // Check merkle roots.
                            if (i == 0) {
                                if (t_polynomials != proof.round_proofs[i].p.root())
                                    return false;
                            } else {
                                if (proof.round_proofs[i - 1].colinear_path.root() != proof.round_proofs[i].T_root)
                                    return false;
                            }
                        }

                        typename FRI::polynomials_values_type y;
                        if constexpr (!FRI::is_const_size) {
                            y.resize(leaf_size);
                        }
                        if (basis_index == 0) {
                            y = y_0;
                        } else {
                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                y[polynom_index].resize(proof.get_y(i)[polynom_index].size());
                                for (std::size_t y_i = 0; y_i < y[polynom_index].size(); y_i++) {
                                    for (std::size_t j = 0; j < FRI::m; j++) {
                                        y[polynom_index][y_i][j] = proof.get_y(i)[polynom_index][y_i][j];
                                    }
                                }
                            }
                        }
                        for (std::size_t step_i = 0; step_i < fri_params.step_list[i] - 1; step_i++, basis_index++) {
                            typename FRI::field_type::value_type alpha =
                                transcript.template challenge<typename FRI::field_type>();

                            for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                                typename FRI::polynomial_values_type y_poly_i_new(y[polynom_index].size() / FRI::m);
                                for (std::size_t y_i = 0; y_i < y_poly_i_new.size(); y_i++) {
                                    std::vector<std::pair<typename FRI::field_type::value_type,
                                                          typename FRI::field_type::value_type>>
                                        interpolation_points_l {
                                            std::make_pair(s[2 * y_i][0], y[polynom_index][2 * y_i][0]),
                                            std::make_pair(s[2 * y_i][1], y[polynom_index][2 * y_i][1]),
                                        };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_l =
                                        math::lagrange_interpolation(interpolation_points_l);
                                    y_poly_i_new[y_i][0] = interpolant_l.evaluate(alpha);
                                    std::vector<std::pair<typename FRI::field_type::value_type,
                                                          typename FRI::field_type::value_type>>
                                        interpolation_points_r {
                                            std::make_pair(s[2 * y_i + 1][0], y[polynom_index][2 * y_i + 1][0]),
                                            std::make_pair(s[2 * y_i + 1][1], y[polynom_index][2 * y_i + 1][1]),
                                        };
                                    math::polynomial<typename FRI::field_type::value_type> interpolant_r =
                                        math::lagrange_interpolation(interpolation_points_r);
                                    y_poly_i_new[y_i][1] = interpolant_r.evaluate(alpha);
                                }
                                y[polynom_index] = std::move(y_poly_i_new);
                            }

                            x_index = x_index % (fri_params.D[basis_index + 1]->size());
                            x = x * x;
                            if (step_i < fri_params.step_list[i] - 1) {
                                std::tie(s, s_indices) = calculate_s<FRI>(
                                    x, x_index, fri_params.step_list[i] - 1 - step_i, fri_params.D[basis_index + 1]);
                            }
                        }

                        basis_index++;
                        x_index_next = x_index % (fri_params.D[basis_index]->size());
                        x_next = x * x;
                        std::tie(s, s_indices) = calculate_s<FRI>(x_next, x_index_next, fri_params.step_list[i + 1],
                                                                  fri_params.D[basis_index]);

                        const std::size_t coset_size = 1 << fri_params.step_list[i + 1];
                        auto correct_order_idx = get_correct_order<FRI>(x_index_next, fri_params.D[basis_index]->size(),
                                                                        fri_params.step_list[i + 1], s_indices);
                        std::vector<std::uint8_t> leaf_data(coset_size * FRI::field_element_type::length() * leaf_size);
                        auto write_iter = leaf_data.begin();

                        typename FRI::field_type::value_type alpha =
                            transcript.template challenge<typename FRI::field_type>();
                        for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {
                            BOOST_ASSERT(y[polynom_index].size() == 1);
                            std::vector<
                                std::pair<typename FRI::field_type::value_type, typename FRI::field_type::value_type>>
                                interpolation_points {
                                    std::make_pair(x, y[polynom_index][0][0]),
                                    std::make_pair(-x, y[polynom_index][0][1]),
                                };

                            math::polynomial<typename FRI::field_type::value_type> interpolant =
                                math::lagrange_interpolation(interpolation_points);

                            if (interpolant.evaluate(alpha) !=
                                proof.get_colinear_value(i)[polynom_index][0][0]) {    // colinear value
                                return false;
                            }

                            for (auto [idx, pair_idx] : correct_order_idx) {
                                typename FRI::field_element_type leaf_val0(
                                    proof.get_colinear_value(i)[polynom_index][idx][pair_idx]);
                                leaf_val0.write(write_iter, FRI::field_element_type::length());
                                typename FRI::field_element_type leaf_val1(
                                    proof.get_colinear_value(i)[polynom_index][idx][(pair_idx + 1) % FRI::m]);
                                leaf_val1.write(write_iter, FRI::field_element_type::length());
                            }
                        }

                        transcript(proof.round_proofs[i].colinear_path.root());
                        if (!proof.round_proofs[i].colinear_path.validate(leaf_data)) {
                            return false;
                        }

                        x_index = x_index_next;
                        x = x_next;
                    }

                    auto final_root = commit<FRI>(precommit<FRI>(
                        proof.final_polynomials, 
                        fri_params.D[basis_index], 
                        fri_params.step_list[fri_params.step_list.size()-1]
                    ));
                    if (final_root != proof.round_proofs[fri_params.step_list.size() - 2].colinear_path.root()) {
                        return false;
                    }

                    for (std::size_t polynom_index = 0; polynom_index < leaf_size; polynom_index++) {

                        if (proof.final_polynomials[polynom_index].degree() >
                            std::pow(2, std::log2(fri_params.max_degree + 1) - r + 1) - 1) {
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
