//---------------------------------------------------------------------------//
// Copyright (c) 2024 Martun Karapetyan <martun@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_PREPROCESSED_PUBLIC_DATA_HPP
#define CRYPTO3_MARSHALLING_PREPROCESSED_PUBLIC_DATA_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/marshalling/math/types/polynomial.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/plonk_public_polynomial_dfs_table.hpp>
#include <nil/crypto3/marshalling/zk/types/placeholder/common_data.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // ******************* placeholder preprocessed public data ********************************* //
                template<typename TTypeBase, typename PreprocessedPublicDataType>
                using placeholder_preprocessed_public_data = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // plonk_public_polynomial_dfs_table<FieldType> public_polynomial_table;
                        plonk_public_polynomial_table<TTypeBase, typename PreprocessedPublicDataType::plonk_public_polynomial_dfs_table_type>,
                        // std::vector<polynomial_dfs_type>  permutation_polynomials
                        polynomial_vector<TTypeBase, typename PreprocessedPublicDataType::polynomial_dfs_type>,

                        // std::vector<polynomial_dfs_type>  identity_polynomials;
                        polynomial_vector<TTypeBase, typename PreprocessedPublicDataType::polynomial_dfs_type>,

                        // polynomial_dfs_type               q_last;
                        typename polynomial<TTypeBase, typename PreprocessedPublicDataType::polynomial_dfs_type>::type,
                        // polynomial_dfs_type               q_blind;
                        typename polynomial<TTypeBase, typename PreprocessedPublicDataType::polynomial_dfs_type>::type,

                        // common_data_type common_data;
                        placeholder_common_data<TTypeBase, typename PreprocessedPublicDataType::common_data_type>
                    >
                >;

                template<typename Endianness, typename PreprocessedPublicDataType>
                placeholder_preprocessed_public_data<nil::marshalling::field_type<Endianness>, PreprocessedPublicDataType>
                fill_placeholder_preprocessed_public_data(const PreprocessedPublicDataType& preprocessed_public_data) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using PolynomialDFSType = typename PreprocessedPublicDataType::polynomial_dfs_type;
                    using result_type = placeholder_preprocessed_public_data<
                        nil::marshalling::field_type<Endianness>, PreprocessedPublicDataType>;

                    return result_type(std::make_tuple(
                        fill_plonk_public_table<Endianness, typename PreprocessedPublicDataType::plonk_public_polynomial_dfs_table_type>(
                            preprocessed_public_data.public_polynomial_table),
                        fill_polynomial_vector<Endianness, PolynomialDFSType>(preprocessed_public_data.permutation_polynomials),
                        fill_polynomial_vector<Endianness, PolynomialDFSType>(preprocessed_public_data.identity_polynomials),
                        fill_polynomial<Endianness, PolynomialDFSType>(preprocessed_public_data.q_last),
                        fill_polynomial<Endianness, PolynomialDFSType>(preprocessed_public_data.q_blind),
                        fill_placeholder_common_data<Endianness, typename PreprocessedPublicDataType::common_data_type>(
                            preprocessed_public_data.common_data)
                    ));
                }

                template<typename Endianness, typename PreprocessedPublicDataType>
                PreprocessedPublicDataType make_placeholder_preprocessed_public_data(const
                    placeholder_preprocessed_public_data<nil::marshalling::field_type<Endianness>, PreprocessedPublicDataType> &filled_preprocessed_public_data
                ) {
                    using TTypeBase = typename nil::marshalling::field_type<Endianness>;
                    using PolynomialDFSType = typename PreprocessedPublicDataType::polynomial_dfs_type;

                    return PreprocessedPublicDataType({
                        make_plonk_public_table<Endianness, typename PreprocessedPublicDataType::plonk_public_polynomial_dfs_table_type>(
                            std::get<0>(filled_preprocessed_public_data.value())),
                        make_polynomial_vector<Endianness, PolynomialDFSType>(std::get<1>(filled_preprocessed_public_data.value())),
                        make_polynomial_vector<Endianness, PolynomialDFSType>(std::get<2>(filled_preprocessed_public_data.value())),
                        make_polynomial<Endianness, PolynomialDFSType>(std::get<3>(filled_preprocessed_public_data.value())),
                        make_polynomial<Endianness, PolynomialDFSType>(std::get<4>(filled_preprocessed_public_data.value())),
                        make_placeholder_common_data<Endianness, typename PreprocessedPublicDataType::common_data_type>(
                            std::get<5>(filled_preprocessed_public_data.value()))
                    });
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_PREPROCESSED_PUBLIC_DATA_HPP
