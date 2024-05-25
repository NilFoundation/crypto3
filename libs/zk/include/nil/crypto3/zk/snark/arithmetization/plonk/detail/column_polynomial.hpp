//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_TABLE_DETAIL_COLUMN_POLYNOMIAL_HPP
#define CRYPTO3_ZK_PLONK_TABLE_DETAIL_COLUMN_POLYNOMIAL_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>

#include <nil/crypto3/zk/math/permutation.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename FieldType>
                    math::polynomial<typename FieldType::value_type>
                        column_polynomial(const plonk_column<FieldType> &column_assignment,
                                          std::shared_ptr<math::evaluation_domain<FieldType>>
                                              domain) {

                        std::vector<typename FieldType::value_type> interpolation_points(column_assignment.size());

                        std::copy(column_assignment.begin(), column_assignment.end(), interpolation_points.begin());

                        domain->inverse_fft(interpolation_points);

                        return nil::crypto3::math::polynomial<typename FieldType::value_type> {interpolation_points};
                    }

                    template<typename FieldType>
                    std::vector<math::polynomial<typename FieldType::value_type>>
                        column_range_polynomials(const std::vector<plonk_column<FieldType>> &column_range_assignment,
                                                 std::shared_ptr<math::evaluation_domain<FieldType>>
                                                     domain) {

                        std::size_t columns_amount = column_range_assignment.size();
                        std::vector<math::polynomial<typename FieldType::value_type>> columns(columns_amount);

                        for (std::size_t column_index = 0; column_index < columns_amount; column_index++) {
                            columns[column_index] =
                                column_polynomial<FieldType>(column_range_assignment[column_index], domain);
                        }

                        return columns;
                    }

                    template<typename FieldType, std::size_t columns_amount>
                    std::array<math::polynomial<typename FieldType::value_type>, columns_amount>
                        column_range_polynomials(
                            const std::array<plonk_column<FieldType>, columns_amount> &column_range_assignment,
                            std::shared_ptr<math::evaluation_domain<FieldType>>
                                domain) {

                        std::array<math::polynomial<typename FieldType::value_type>, columns_amount> columns;

                        for (std::size_t column_index = 0; column_index < columns_amount; column_index++) {
                            columns[column_index] =
                                column_polynomial<FieldType>(column_range_assignment[column_index], domain);
                        }

                        return columns;
                    }

                    template<typename FieldType>
                    math::polynomial_dfs<typename FieldType::value_type>
                        column_polynomial_dfs(plonk_column<FieldType> column_assignment,
                                              std::shared_ptr<math::evaluation_domain<FieldType>> domain) {

                        std::size_t d = std::distance(column_assignment.begin(), column_assignment.end()) - 1;

                        nil::crypto3::math::polynomial_dfs<typename FieldType::value_type> res(
                            d, column_assignment.begin(), column_assignment.end());

                        res.resize(domain->size());

                        return res;
                    }

                    template<typename FieldType>
                    std::vector<math::polynomial_dfs<typename FieldType::value_type>>
                        column_range_polynomial_dfs(std::vector<plonk_column<FieldType>> column_range_assignment,
                                                    std::shared_ptr<math::evaluation_domain<FieldType>> domain) {

                        std::size_t columns_amount = column_range_assignment.size();
                        std::vector<math::polynomial_dfs<typename FieldType::value_type>> columns(columns_amount);

                        for (std::size_t column_index = 0; column_index < columns_amount; column_index++) {
                            columns[column_index] =
                                column_polynomial_dfs<FieldType>(std::move(column_range_assignment[column_index]), domain);
                        }

                        return columns;
                    }

                    template<typename FieldType, std::size_t columns_amount>
                    std::array<math::polynomial_dfs<typename FieldType::value_type>, columns_amount>
                        column_range_polynomial_dfs(
                            std::array<plonk_column<FieldType>, columns_amount> column_range_assignment,
                            std::shared_ptr<math::evaluation_domain<FieldType>>
                                domain) {

                        std::array<math::polynomial_dfs<typename FieldType::value_type>, columns_amount> columns;

                        for (std::size_t column_index = 0; column_index < columns_amount; column_index++) {
                            columns[column_index] =
                                column_polynomial_dfs<FieldType>(std::move(column_range_assignment[column_index]), domain);
                        }

                        return columns;
                    }
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_TABLE_DETAIL_COLUMN_POLYNOMIAL_HPP
