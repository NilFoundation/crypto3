//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_MATH_VARIABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_MATH_VARIABLE_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename Variable, typename = void>
                struct variable;

                template<typename TTypeBase, typename Field>
                struct variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<Field>> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase, std::tuple<
                                       // int rotation
                                       nil::marshalling::types::integral<TTypeBase, int>,
                                       // enum column_type { witness, public_input, constant, selector } type
                                       nil::marshalling::types::integral<TTypeBase, int>,
                                       // std::size_t index
                                       nil::marshalling::types::integral<TTypeBase, std::size_t>,
                                       // bool relative
                                       nil::marshalling::types::integral<TTypeBase, bool>>>;
                };

                template<typename Variable, typename Endianness, typename Field = typename Variable::field_type>
                typename std::enable_if<
                    std::is_same<Variable, nil::crypto3::zk::snark::plonk_variable<Field>>::value,
                    typename variable<nil::marshalling::field_type<Endianness>, Variable>::type>::type
                    fill_variable(const Variable &var) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = typename variable<TTypeBase, Variable>::type;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using int_marshalling_type = nil::marshalling::types::integral<TTypeBase, int>;
                    using bool_marshalling_type = nil::marshalling::types::integral<TTypeBase, bool>;

                    return result_type(
                        std::make_tuple(int_marshalling_type(var.rotation), int_marshalling_type(var.type),
                                        size_t_marshalling_type(var.index), bool_marshalling_type(var.relative)));
                }

                template<typename Variable, typename Endianness, typename Field = typename Variable::field_type>
                typename std::enable_if<std::is_same<Variable, nil::crypto3::zk::snark::plonk_variable<Field>>::value,
                                        Variable>::type
                    make_variable(
                        const typename variable<nil::marshalling::field_type<Endianness>, Variable>::type &filled_var) {

                    return Variable(std::get<2>(filled_var.value()).value(),
                                    std::get<0>(filled_var.value()).value(),
                                    std::get<3>(filled_var.value()).value(),
                                    typename Variable::column_type(std::get<1>(filled_var.value()).value()));
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_MATH_VARIABLE_HPP
