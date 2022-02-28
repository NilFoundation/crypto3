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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP

#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include "nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp"
#include <nil/crypto3/zk/snark/relations/plonk/permutation.hpp>

using namespace nil::crypto3;

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename FieldType>
                    math::polynomial<typename FieldType::value_type>
                        column_polynomial(const plonk_column<FieldType> &column_assignment,
                                          const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {

                        std::vector<typename FieldType::value_type> interpolation_points(column_assignment.size());

                        std::copy(column_assignment.begin(), column_assignment.end(), interpolation_points.begin());

                        domain->inverse_fft(interpolation_points);

                        return interpolation_points;
                    }

                    template<typename FieldType>
                    std::vector<math::polynomial<typename FieldType::value_type>>
                        column_range_polynomials(const std::vector<plonk_column<FieldType>> &column_range_assignment,
                                                 const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {

                        std::size_t columns_amount = column_range_assignment.size();
                        std::vector<math::polynomial<typename FieldType::value_type>> columns(columns_amount);

                        for (std::size_t selector_index = 0; selector_index < columns_amount; selector_index++) {
                            columns[selector_index] =
                                column_polynomial<FieldType>(column_range_assignment[selector_index], domain);
                        }

                        return columns;
                    }

                    template<typename FieldType, std::size_t columns_amount>
                    std::array<math::polynomial<typename FieldType::value_type>, columns_amount>
                        column_range_polynomials(
                            const std::array<plonk_column<FieldType>, columns_amount> &column_range_assignment,
                            const std::shared_ptr<math::evaluation_domain<FieldType>> &domain) {

                        std::array<math::polynomial<typename FieldType::value_type>, columns_amount> columns;

                        for (std::size_t selector_index = 0; selector_index < columns_amount; selector_index++) {
                            columns[selector_index] =
                                column_polynomial<FieldType>(column_range_assignment[selector_index], domain);
                        }

                        return columns;
                    }

                }    // namespace detail

                template<typename FieldType, typename ParamsType, std::size_t k>
                class redshift_public_preprocessor {
                    typedef detail::redshift_policy<FieldType, ParamsType> policy_type;

                    static math::polynomial<typename FieldType::value_type>
                        lagrange_polynomial(std::shared_ptr<math::evaluation_domain<FieldType>> domain,
                                            std::size_t number) {
                        std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>>
                            evaluation_points;
                        for (std::size_t i = 0; i < domain->m; i++) {
                            evaluation_points.push_back(std::make_pair(domain->get_domain_element(i),
                                                                       (i != number) ? FieldType::value_type::zero() :
                                                                                       FieldType::value_type::one()));
                        }
                        math::polynomial<typename FieldType::value_type> f =
                            math::lagrange_interpolation(evaluation_points);

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
                            tmp[j] = j > usable_rows ? FieldType::value_type::one() : FieldType::value_type::zero();
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
                            tmp[j] = j == usable_rows ? FieldType::value_type::one() : FieldType::value_type::zero();
                        }

                        domain->inverse_fft(tmp);
                        math::polynomial<typename FieldType::value_type> q_last(tmp);

                        return q_last;
                    }

                    template<typename CommitmentSchemeType>
                    static inline typename policy_type::preprocessed_public_data_type process(
                        const typename policy_type::constraint_system_type &constraint_system,
                        const typename policy_type::variable_assignment_type::public_table_type &public_assignment,
                        typename policy_type::template circuit_short_description<CommitmentSchemeType>
                            &short_description) {

                        std::size_t N_rows = constraint_system.rows_amount();

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            math::make_evaluation_domain<FieldType>(N_rows);

                        std::vector<math::polynomial<typename FieldType::value_type>> _permutation_polynomials =
                            permutation_polynomials(short_description.columns_with_copy_constraints.size(),
                                                    short_description.table_rows, basic_domain->get_domain_element(1),
                                                    short_description.delta, short_description.permutation,
                                                    basic_domain);

                        std::vector<math::polynomial<typename FieldType::value_type>> _identity_polynomials =
                            identity_polynomials(short_description.columns_with_copy_constraints.size(),
                                                 short_description.table_rows, basic_domain->get_domain_element(1),
                                                 short_description.delta, basic_domain);

                        math::polynomial<typename FieldType::value_type> lagrange_0 =
                            lagrange_polynomial(basic_domain, 0);

                        math::polynomial<typename FieldType::value_type> q_last =
                            selector_last(short_description.table_rows, short_description.usable_rows, basic_domain);
                        math::polynomial<typename FieldType::value_type> q_blind =
                            selector_blind(short_description.table_rows, short_description.usable_rows, basic_domain);

                        plonk_public_polynomial_table<FieldType> public_polynomial_table =
                            plonk_public_polynomial_table<FieldType>(
                                detail::column_range_polynomials<FieldType>(public_assignment.selectors(),
                                                                            basic_domain),
                                detail::column_range_polynomials<FieldType>(public_assignment.public_inputs(),
                                                                            basic_domain));

                        std::vector<typename FieldType::value_type> z_numenator(N_rows + 1);
                        z_numenator[0] = -FieldType::value_type::one();
                        z_numenator[N_rows] = FieldType::value_type::one();

                        math::polynomial<typename FieldType::value_type> Z = z_numenator;
                        math::polynomial<typename FieldType::value_type> z_denominator = {-FieldType::value_type::one(),
                                                                                          FieldType::value_type::one()};
                        Z = Z / z_denominator;

                        return typename policy_type::preprocessed_public_data_type(
                            {basic_domain, public_polynomial_table, _permutation_polynomials, _identity_polynomials,
                             lagrange_0, q_last, q_blind, Z});
                    }
                };

                template<typename FieldType, typename RedshiftParams, std::size_t k>
                class redshift_private_preprocessor {
                    using policy_type = detail::redshift_policy<FieldType, RedshiftParams>;

                public:
                    template<typename CommitmentSchemeType>
                    static inline typename policy_type::preprocessed_private_data_type process(
                        const typename policy_type::constraint_system_type &constraint_system,
                        const typename policy_type::variable_assignment_type::private_table_type &private_assignment,
                        typename policy_type::template circuit_short_description<CommitmentSchemeType>
                            &short_description) {

                        std::size_t N_rows = constraint_system.rows_amount();

                        std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain =
                            math::make_evaluation_domain<FieldType>(N_rows);

                        plonk_private_polynomial_table<FieldType, RedshiftParams::witness_columns> private_polynomial_table =
                            plonk_private_polynomial_table<FieldType, RedshiftParams::witness_columns>(
                                detail::column_range_polynomials<FieldType>(private_assignment.witnesses(),
                                                                            basic_domain));

                        return typename policy_type::preprocessed_private_data_type(
                            {basic_domain, private_polynomial_table});
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_REDSHIFT_PREPROCESSOR_HPP
