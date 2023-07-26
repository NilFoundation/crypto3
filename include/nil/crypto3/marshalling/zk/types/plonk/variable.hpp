//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_VARIABLE_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_VARIABLE_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename Variable, typename = void>
                struct variable;
                
                /********************************* plonk_variable ***************************/
                template<typename TTypeBase, typename AssignmentType>
                struct variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<AssignmentType>> {
                    using type = nil::marshalling::types::bundle<
                        TTypeBase,
                        std::tuple<
                            // std::size_t index
                            nil::marshalling::types::integral<TTypeBase, std::size_t>,
                            // std::int32_t rotation
                            nil::marshalling::types::integral<TTypeBase, std::int32_t>,
                            // bool relative
                            nil::marshalling::types::integral<TTypeBase, bool>,
                            // enum column_type : std::uint8_t { witness, public_input, constant, selector } type
                            nil::marshalling::types::integral<TTypeBase, std::uint8_t>>>;
                };

                template<typename Variable, typename Endianness>
                typename std::enable_if<
                    std::is_same<Variable,
                                 nil::crypto3::zk::snark::plonk_variable<typename Variable::assignment_type>>::value,
                    typename variable<nil::marshalling::field_type<Endianness>, Variable>::type>::type
                fill_variable(const Variable &var) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = typename variable<TTypeBase, Variable>::type;
                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using int32_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::int32_t>;
                    using octet_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::uint8_t>;
                    using bool_marshalling_type = nil::marshalling::types::integral<TTypeBase, bool>;

                    return result_type(
                        std::make_tuple(size_t_marshalling_type(var.index), int32_marshalling_type(var.rotation),
                                        bool_marshalling_type(var.relative), octet_marshalling_type(var.type)));
                }

                template<typename Variable, typename Endianness>
                typename std::enable_if<std::is_same<Variable, nil::crypto3::zk::snark::plonk_variable<
                                                                   typename Variable::assignment_type>>::value,
                                        Variable>::type
                    make_variable(
                        const typename variable<nil::marshalling::field_type<Endianness>, Variable>::type &filled_var) {

                    return Variable(std::get<0>(filled_var.value()).value(),
                                    std::get<1>(filled_var.value()).value(),
                                    std::get<2>(filled_var.value()).value(),
                                    typename Variable::column_type(std::get<3>(filled_var.value()).value()));
                }

                /****************** vector of plonk_variable *************************/
                template<typename TTypeBase, typename AssignmentType>
                using variables = nil::marshalling::types::array_list<
                    TTypeBase, 
                    typename variable<TTypeBase, nil::crypto3::zk::snark::plonk_variable<AssignmentType>>::type,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Variable, typename Endianness>
                variables<nil::marshalling::field_type<Endianness>, typename Variable::assignment_type>
                fill_variables(const std::vector<Variable> &vars) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using AssignmentType = typename Variable::assignment_type;

                    variables<TTypeBase, AssignmentType> filled_vars;
                    for (const auto &var : vars) {
                        filled_vars.value().push_back(fill_variable<Variable, Endianness>(var));
                    }

                    return filled_vars;
                }

                template<typename Variable, typename Endianness>
                std::vector<Variable>
                make_variables(const variables<nil::marshalling::field_type<Endianness>, typename Variable::assignment_type> &filled_vars){
                    std::vector<Variable> vars;
                    for (std::size_t i = 0; i < filled_vars.value().size(); i++) {
                        vars.emplace_back(make_variable<Variable, Endianness>(filled_vars.value().at(i)));
                    }
                    return vars;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_VARIABLE_HPP
