//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/types.hpp>
#include <nil/crypto3/zk/snark/relations/plonk/permutation.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, std::size_t WitnessColumns, std::size_t PublicColumns, std::size_t k>
                class redshift_preprocessor {
                    using types_policy = detail::redshift_types_policy<FieldType, WitnessColumns, PublicColumns>;

                    static math::polynomial<typename FieldType::value_type>
                        lagrange_polynomial(std::shared_ptr<math::evaluation_domain<FieldType>> domain, std::size_t number) {
                        std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> evaluation_points;
                        for (std::size_t i = 0; i < domain->m; i++) {
                            evaluation_points.push_back(std::make_pair(domain->get_domain_element(i), (i != number) ?
                                                                                                        FieldType::value_type::zero() :
                                                                                                        FieldType::value_type::one()));
                        }
                        math::polynomial<typename FieldType::value_type> f = math::lagrange_interpolation(evaluation_points);

                        return f;
                    }

                public:
                    static inline std::vector<math::polynomial<typename FieldType::value_type>>
                        identity_polynomials(std::size_t permutation_size, std::size_t table_size,
                            const typename FieldType::value_type &omega, 
                            const typename FieldType::value_type &delta,
                            const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {
                            
                            std::vector<math::polynomial<typename FieldType::value_type>> S_id(permutation_size);

                            for (std::size_t i = 0; i < permutation_size; i++) {
                                std::vector<typename FieldType::value_type> tmp(table_size);
                                for (std::size_t j = 0; j < table_size; j++) {
                                    tmp[j] = delta.pow(i) * omega.pow(j);
                                }

                                domain->inverse_fft(tmp);
                                S_id[i] = math::polynomial<typename FieldType::value_type>(tmp);
                            }

                            return S_id;
                    }

                    static inline std::vector<math::polynomial<typename FieldType::value_type>>
                        permutation_polynomials(std::size_t permutation_size, std::size_t table_size,
                            const typename FieldType::value_type &omega, 
                            const typename FieldType::value_type &delta,
                            plonk_permutation &permutation,
                            const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {
                            
                            std::vector<math::polynomial<typename FieldType::value_type>> S_perm(permutation_size);

                            for (std::size_t i = 0; i < permutation_size; i++) {
                                std::vector<typename FieldType::value_type> tmp(table_size);
                                for (std::size_t j = 0; j < table_size; j++) {
                                    auto key = std::make_pair(i, j);
                                    tmp[j] = delta.pow(permutation[key].first) * omega.pow(permutation[key].second);
                                }

                                domain->inverse_fft(tmp);
                                S_perm[i] = math::polynomial<typename FieldType::value_type>(tmp);
                            }

                            return S_perm;
                    }

                    static inline math::polynomial<typename FieldType::value_type>
                        selector_blind(std::size_t table_size, std::size_t usable_rows,
                            const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {

                            std::vector<typename FieldType::value_type> tmp(table_size);
                            for (std::size_t j = 0; j < table_size; j++) {
                                tmp[j] = j > usable_rows ?  FieldType::value_type::one() : FieldType::value_type::zero();
                            }

                            domain->inverse_fft(tmp);
                            math::polynomial<typename FieldType::value_type> q_blind(tmp);

                            return q_blind;
                    }

                    static inline math::polynomial<typename FieldType::value_type>
                        selector_last(std::size_t table_size, std::size_t usable_rows,
                            const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {

                            std::vector<typename FieldType::value_type> tmp(table_size);
                            for (std::size_t j = 0; j < table_size; j++) {
                                tmp[j] = j == usable_rows ?  FieldType::value_type::one() : FieldType::value_type::zero();
                            }

                            domain->inverse_fft(tmp);
                            math::polynomial<typename FieldType::value_type> q_last(tmp);

                            return q_last;
                    }

                    template <typename lpc_type>
                    static inline typename types_policy::template preprocessed_data_type<WitnessColumns>
                        process(const typename types_policy::constraint_system_type &constraint_system,
                                const typename types_policy::variable_assignment_type &assignments,
                                typename types_policy::template circuit_short_description<lpc_type> &short_description) {

                        typename types_policy::template preprocessed_data_type<WitnessColumns> data;

                        std::size_t N_rows = 0;
                        for (auto &wire_assignments : assignments) {
                            N_rows = std::max(N_rows, wire_assignments.size());
                        }

                        data.basic_domain = math::make_evaluation_domain<FieldType>(N_rows);


                        data.permutation_polynomials = permutation_polynomials(short_description.columns_with_copy_constraints.size(), 
                            short_description.table_rows, data.basic_domain->get_domain_element(1), short_description.delta, 
                            short_description.permutation, data.basic_domain);

                        data.identity_polynomials = identity_polynomials(short_description.columns_with_copy_constraints.size(), 
                            short_description.table_rows, data.basic_domain->get_domain_element(1), 
                            short_description.delta, data.basic_domain);

                        data.lagrange_0 = lagrange_polynomial(data.basic_domain, 0);

                        data.q_last = selector_last(short_description.table_rows, short_description.usable_rows, data.basic_domain);
                        data.q_blind = selector_blind(short_description.table_rows, short_description.usable_rows, data.basic_domain);

                        /*data.omega = math::unity_root<FieldType>(math::detail::power_of_two(k));
                        data.Z = {1};
                        // data.selectors = constraint_system.selectors();
                        // ... copy_constraints = constraint_system.copy_constraints();

                        // data.permutations = ...(copy_constraints);
                        // data.identity_permutations = ...(copy_constraints);

                        // data.Lagrange_basis = math::polynomial::Lagrange_basis(data.omega, ...(assignments).n);*/

                        return data;
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP
