//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_COMMON_DATA_HPP
#define CRYPTO3_MARSHALLING_COMMON_DATA_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/lpc.hpp>

#include <nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename RedshiftPolicy,
                         typename = typename std::enable_if<
                             std::is_same<RedshiftPolicy, nil::crypto3::zk::snark::detail::redshift_policy<
                                                              typename RedshiftPolicy::field_type,
                                                              typename RedshiftPolicy::redshift_params_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using redshift_verifier_common_data = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::size_t rows_amount;
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        // omega
                        field_element<TTypeBase, typename RedshiftPolicy::field_type::value_type>,
                        // std::array<std::vector<int>, arithmetization_params::TotalColumns> columns_rotations;
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            nil::marshalling::types::array_list<
                                TTypeBase, nil::marshalling::types::integral<TTypeBase, int>,
                                nil::marshalling::option::sequence_size_field_prefix<
                                    nil::marshalling::types::integral<TTypeBase, std::size_t>>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename RedshiftPolicy, typename Endianness>
                redshift_verifier_common_data<nil::marshalling::field_type<Endianness>, RedshiftPolicy>
                    fill_redshift_verifier_common_data(
                        const typename RedshiftPolicy::preprocessed_public_data_type::common_data_type &common_data) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using int_marshalling_type = nil::marshalling::types::integral<TTypeBase, int>;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using int_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, int_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using int_vector_vector_marshalling_type = nil::marshalling::types::array_list<
                        TTypeBase, int_vector_marshalling_type,
                        nil::marshalling::option::sequence_size_field_prefix<size_t_marshalling_type>>;
                    using field_element_marshalling_type =
                        field_element<TTypeBase, typename RedshiftPolicy::field_type::value_type>;

                    // std::size_t rows_amount;
                    size_t_marshalling_type filled_rows_amount(common_data.rows_amount);

                    // omega
                    field_element_marshalling_type filled_omega(common_data.basic_domain->get_domain_element(1));

                    // std::array<std::vector<int>, arithmetization_params::TotalColumns> columns_rotations;
                    int_vector_vector_marshalling_type filled_columns_rotations;
                    for (const auto &column_rotations : common_data.columns_rotations) {
                        int_vector_marshalling_type filled_column_rotations;
                        for (auto column_rotation : column_rotations) {
                            filled_column_rotations.value().push_back(int_marshalling_type(column_rotation));
                        }
                        filled_columns_rotations.value().push_back(filled_column_rotations);
                    }

                    return redshift_verifier_common_data<TTypeBase, RedshiftPolicy>(
                        std::make_tuple(filled_rows_amount, filled_omega, filled_columns_rotations));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_COMMON_DATA_HPP
