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

#ifndef CRYPTO3_MARSHALLING_R1CS_HPP
#define CRYPTO3_MARSHALLING_R1CS_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/detail/adapt_basic_field.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

#include <nil/crypto3/container/sparse_vector.hpp>

#include <nil/crypto3/marshalling/algebra/types/curve_element.hpp>
#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase,
                         typename LT,
                         typename = typename std::enable_if<
                             std::is_same<LT, math::linear_term<math::linear_variable<typename LT::field_type>>>::value,
                             bool>::type,
                         typename... TOptions>
                using linear_term = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // index
                        nil::marshalling::types::
                            integral<TTypeBase, typename math::linear_variable<typename LT::field_type>::index_type>,
                        // coeff
                        field_element<TTypeBase, typename LT::field_type::value_type>>>;

                template<typename TTypeBase,
                         typename LC,
                         typename = typename std::enable_if<
                             std::is_same<LC, math::linear_combination<math::linear_variable<typename LC::field_type>>>::value,
                             bool>::type,
                         typename... TOptions>
                using linear_combination = nil::marshalling::types::array_list<
                    TTypeBase,
                    linear_term<TTypeBase, math::linear_term<math::linear_variable<typename LC::field_type>>>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<TTypeBase, std::size_t>>>;

                template<
                    typename TTypeBase,
                    typename Constraint,
                    typename = typename std::enable_if<
                        std::is_same<Constraint, zk::snark::r1cs_constraint<typename Constraint::field_type>>::value,
                        bool>::type,
                    typename... TOptions>
                using r1cs_constraint = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // a
                        linear_combination<TTypeBase, math::linear_combination<math::linear_variable<typename Constraint::field_type>>>,
                        // b
                        linear_combination<TTypeBase, math::linear_combination<math::linear_variable<typename Constraint::field_type>>>,
                        // c
                        linear_combination<TTypeBase, math::linear_combination<math::linear_variable<typename Constraint::field_type>>>>>;

                template<typename TTypeBase,
                         typename CS,
                         typename = typename std::enable_if<
                             std::is_same<CS, zk::snark::r1cs_constraint_system<typename CS::field_type>>::value,
                             bool>::type,
                         typename... TOptions>
                using r1cs_constraint_system = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // primary_input_size
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        // auxiliary_input_size
                        nil::marshalling::types::integral<TTypeBase, std::size_t>,
                        // constraints
                        nil::marshalling::types::array_list<
                            TTypeBase,
                            r1cs_constraint<TTypeBase, zk::snark::r1cs_constraint<typename CS::field_type>>,
                            nil::marshalling::option::sequence_size_field_prefix<
                                nil::marshalling::types::integral<TTypeBase, std::size_t>>>>>;

                template<typename LT, typename Endianness>
                linear_term<nil::marshalling::field_type<Endianness>, LT> fill_linear_term(const LT &lt) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using integral_type = nil::marshalling::types::
                        integral<TTypeBase, typename math::linear_variable<typename LT::field_type>::index_type>;
                    using field_element_type = field_element<TTypeBase, typename LT::field_type::value_type>;

                    return linear_term<TTypeBase, LT>(
                        std::make_tuple(integral_type(lt.index), field_element_type(lt.coeff)));
                }

                template<typename LT, typename Endianness>
                LT make_linear_term(const linear_term<nil::marshalling::field_type<Endianness>, LT> &filled_lt) {
                    return typename LT::variable_type(std::move(std::get<0>(filled_lt.value()).value())) *
                              std::move(std::get<1>(filled_lt.value()).value());
                }

                template<typename LC, typename Endianness>
                linear_combination<nil::marshalling::field_type<Endianness>, LC> fill_linear_combination(const LC &lc) {

                    using lt_type = linear_term<nil::marshalling::field_type<Endianness>,
                                                math::linear_term<math::linear_variable<typename LC::field_type>>>;
                    using lc_type = linear_combination<nil::marshalling::field_type<Endianness>, LC>;

                    lc_type result;
                    std::vector<lt_type> &val = result.value();
                    for (std::size_t i = 0; i < lc.terms.size(); i++) {
                        val.push_back(
                            fill_linear_term<math::linear_term<math::linear_variable<typename LC::field_type>>, Endianness>(lc.terms[i]));
                    }

                    return result;
                }

                template<typename LC, typename Endianness>
                LC make_linear_combination(
                    const linear_combination<nil::marshalling::field_type<Endianness>, LC> &filled_lc) {

                    LC result;
                    const std::vector<linear_term<nil::marshalling::field_type<Endianness>,
                                                  math::linear_term<math::linear_variable<typename LC::field_type>>>> &values =
                        filled_lc.value();
                    std::size_t size = values.size();
                    for (std::size_t i = 0; i < size; i++) {
                        result.add_term(
                            make_linear_term<math::linear_term<math::linear_variable<typename LC::field_type>>, Endianness>(values[i]));
                    }

                    return result;
                }

                template<typename Constraint, typename Endianness>
                r1cs_constraint<nil::marshalling::field_type<Endianness>, Constraint>
                    fill_r1cs_constraint(const Constraint &c) {

                    return r1cs_constraint<nil::marshalling::field_type<Endianness>, Constraint>(std::make_tuple(
                        fill_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                Endianness>(c.a),
                        fill_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                Endianness>(c.b),
                        fill_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                Endianness>(c.c)));
                }

                template<typename Constraint, typename Endianness>
                Constraint make_r1cs_constraint(
                    const r1cs_constraint<nil::marshalling::field_type<Endianness>, Constraint> &filled_c) {

                    return Constraint(
                        std::move(
                            make_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                    Endianness>(std::get<0>(filled_c.value()))),
                        std::move(
                            make_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                    Endianness>(std::get<1>(filled_c.value()))),
                        std::move(
                            make_linear_combination<math::linear_combination<math::linear_variable<typename Constraint::field_type>>,
                                                    Endianness>(std::get<2>(filled_c.value()))));
                }

                template<typename Constraint, typename Endianness>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    r1cs_constraint<nil::marshalling::field_type<Endianness>,
                                    zk::snark::r1cs_constraint<typename Constraint::field_type>>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    fill_r1cs_constraint_vector(const std::vector<Constraint> &cs_vec) {

                    using constraint_type = r1cs_constraint<nil::marshalling::field_type<Endianness>, Constraint>;
                    using constraint_vector_type = nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        constraint_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>;

                    constraint_vector_type result;
                    std::vector<constraint_type> &val = result.value();
                    for (std::size_t i = 0; i < cs_vec.size(); i++) {
                        val.push_back(fill_r1cs_constraint<zk::snark::r1cs_constraint<typename Constraint::field_type>,
                                                           Endianness>(cs_vec[i]));
                    }
                    return result;
                }

                template<typename Constraint, typename Endianness>
                std::vector<Constraint> make_r1cs_constraint_vector(
                    const nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        r1cs_constraint<nil::marshalling::field_type<Endianness>,
                                        zk::snark::r1cs_constraint<typename Constraint::field_type>>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                        &filled_cs_vec) {

                    std::vector<Constraint> result;
                    const std::vector<r1cs_constraint<nil::marshalling::field_type<Endianness>, Constraint>> &values =
                        filled_cs_vec.value();
                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result.push_back(
                            make_r1cs_constraint<zk::snark::r1cs_constraint<typename Constraint::field_type>,
                                                 Endianness>(values[i]));
                    }
                    return result;
                }

                template<typename CS, typename Endianness>
                r1cs_constraint_system<nil::marshalling::field_type<Endianness>, CS>
                    fill_r1cs_constraint_system(const CS &cs) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using integral_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;

                    return r1cs_constraint_system<nil::marshalling::field_type<Endianness>, CS>(std::make_tuple(
                        integral_type(cs.primary_input_size),
                        integral_type(cs.auxiliary_input_size),
                        fill_r1cs_constraint_vector<zk::snark::r1cs_constraint<typename CS::field_type>, Endianness>(
                            cs.constraints)));
                }

                template<typename CS, typename Endianness>
                CS make_r1cs_constraint_system(
                    const r1cs_constraint_system<nil::marshalling::field_type<Endianness>, CS> &filled_cs) {

                    CS result;
                    result.primary_input_size = std::get<0>(filled_cs.value()).value();
                    result.auxiliary_input_size = std::get<1>(filled_cs.value()).value();
                    result.constraints =
                        make_r1cs_constraint_vector<zk::snark::r1cs_constraint<typename CS::field_type>, Endianness>(
                            std::get<2>(filled_cs.value()));

                    return result;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_R1CS_HPP
