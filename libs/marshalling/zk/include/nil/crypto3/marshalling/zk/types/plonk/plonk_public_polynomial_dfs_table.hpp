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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_PUBLIC_POLYNOMIAL_TABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_PUBLIC_POLYNOMIAL_TABLE_HPP

#include <type_traits>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>
#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/math/types/polynomial.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename PlonkPublicTable>
                using plonk_public_polynomial_table = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<
                        // public_inputs
                        polynomial_vector<TTypeBase, typename PlonkPublicTable::column_type>,
                        // constants
                        polynomial_vector<TTypeBase, typename PlonkPublicTable::column_type>,
                        // selectors
                        polynomial_vector<TTypeBase, typename PlonkPublicTable::column_type>
                    >
                >;

                template<typename Endianness, typename PlonkPublicTable>
                plonk_public_polynomial_table<nil::marshalling::field_type<Endianness>, PlonkPublicTable> fill_plonk_public_table(
                    const PlonkPublicTable &public_table
                ) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using PolynomialType = typename PlonkPublicTable::column_type;
                    using result_type = plonk_public_polynomial_table<nil::marshalling::field_type<Endianness>, PlonkPublicTable>;
                    return result_type(std::make_tuple(
                        fill_polynomial_vector<Endianness, PolynomialType>(public_table.public_inputs()),
                        fill_polynomial_vector<Endianness, PolynomialType>(public_table.constants()),
                        fill_polynomial_vector<Endianness, PolynomialType>(public_table.selectors())
                    ));
                }

                template<typename Endianness, typename PlonkPublicTable>
                PlonkPublicTable make_plonk_public_table(
                        const plonk_public_polynomial_table<nil::marshalling::field_type<Endianness>, PlonkPublicTable> &filled_public_table) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using PolynomialType = typename PlonkPublicTable::column_type;
 
                    return PlonkPublicTable(
                        make_polynomial_vector<Endianness, PolynomialType>(std::get<0>(filled_public_table.value())),
                        make_polynomial_vector<Endianness, PolynomialType>(std::get<1>(filled_public_table.value())),
                        make_polynomial_vector<Endianness, PolynomialType>(std::get<2>(filled_public_table.value()))
                    );
                }

            } //namespace types
        } // namespace marshalling
    } // namespace crypto3
} // namespace nil

#endif
