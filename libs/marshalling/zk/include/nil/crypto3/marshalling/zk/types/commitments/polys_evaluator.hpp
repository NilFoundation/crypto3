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

#ifndef CRYPTO3_MARSHALLING_POLYS_EVALUATOR_HPP
#define CRYPTO3_MARSHALLING_POLYS_EVALUATOR_HPP

#include <ratio>
#include <limits>
#include <type_traits>

#include <boost/assert.hpp>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>
#include <nil/crypto3/marshalling/math/types/polynomial.hpp>
#include <nil/crypto3/marshalling/zk/types/commitments/eval_storage.hpp>

#include <nil/crypto3/zk/commitments/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                // * PolysEvaluator is like lpc_commitment_scheme
                template <typename TTypeBase, typename PolysEvaluator>
                using polys_evaluator = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // std::map<std::size_t, std::vector<polynomial_type>> _polys;
                        nil::marshalling::types::standard_size_t_array_list<TTypeBase>,
                        nil::marshalling::types::standard_array_list<
                            TTypeBase,
                            polynomial_vector<TTypeBase, typename PolysEvaluator::polynomial_type>
                        >,
                        // std::map<std::size_t, bool> _locked;
                        nil::marshalling::types::standard_size_t_array_list<TTypeBase>,
                        nil::marshalling::types::standard_size_t_array_list<TTypeBase>,
                        // std::map<std::size_t, std::vector<std::vector<typename field_type::value_type>>> _points;
                        nil::marshalling::types::standard_size_t_array_list<TTypeBase>,
                        // Next structure is a vector of vector of vector of field values.
                        nil::marshalling::types::standard_array_list<
                            TTypeBase,
                            nil::marshalling::types::standard_array_list<
                                TTypeBase,
                                field_element_vector<typename PolysEvaluator::value_type, TTypeBase>
                            >
                        >,
                        // eval_storage<field_type> _z;
                        eval_storage<TTypeBase, typename PolysEvaluator::eval_storage_type>
                    > // This one closes the tuple
                >; // this one closes the bundle

                template <typename Endianness, typename PolysEvaluator>
                polys_evaluator<nil::marshalling::field_type<Endianness>, PolysEvaluator>
                fill_polys_evaluator(const PolysEvaluator& evaluator) {

                    using nil::marshalling::types::fill_size_t;
                    using nil::marshalling::types::fill_std_map;
                    using nil::marshalling::types::standard_array_list;
                    using nil::marshalling::types::fill_standard_array_list;

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using polynomial_type = typename PolysEvaluator::polynomial_type;
                    using value_type = typename polynomial_type::value_type;

                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using polynomial_vector_marshalling_type = polynomial_vector<TTypeBase, polynomial_type>;
                    
                    using field_element_vector_type = field_element_vector<value_type, nil::marshalling::field_type<Endianness>>;
                    using array_of_field_element_vector_type = standard_array_list<TTypeBase, field_element_vector_type>;

                    using result_type = polys_evaluator<nil::marshalling::field_type<Endianness>, PolysEvaluator>;

                    auto [filled_polys_keys, filled_polys_values] = fill_std_map<
                            TTypeBase,
                            size_t_marshalling_type,
                            polynomial_vector_marshalling_type,
                            std::size_t,
                            std::vector<polynomial_type>>(
                        evaluator._polys, fill_size_t<TTypeBase>, fill_polynomial_vector<Endianness, polynomial_type>);

                    // Note that we marshall a bool value as an std::size_t.
                    auto [filled_locked_keys, filled_locked_values] = fill_std_map<
                            TTypeBase,
                            size_t_marshalling_type,
                            size_t_marshalling_type,
                            std::size_t,
                            bool>(
                        evaluator._locked, fill_size_t<TTypeBase>, fill_size_t<TTypeBase>);

                    auto [filled_points_keys, filled_points_values] = fill_std_map<
                            TTypeBase,
                            size_t_marshalling_type,
                            array_of_field_element_vector_type,
                            std::size_t,
                            std::vector<std::vector<value_type>>>(
                        evaluator._points,
                        fill_size_t<TTypeBase>,
                        [](const std::vector<std::vector<value_type>>& points) -> array_of_field_element_vector_type {
                            return fill_standard_array_list<TTypeBase, field_element_vector_type>(
                                points, fill_field_element_vector<value_type, Endianness>);
                        });

                    auto filled_eval_storage = fill_eval_storage<Endianness, typename PolysEvaluator::eval_storage_type>(
                        evaluator._z);

                    return result_type(
                        std::make_tuple(
                            filled_polys_keys,
                            filled_polys_values,
                            filled_locked_keys,
                            filled_locked_values,
                            filled_points_keys,
                            filled_points_values,
                            filled_eval_storage
                        )
                    );
                }

                template <typename Endianness, typename PolysEvaluator>
                PolysEvaluator make_polys_evaluator(
                    const polys_evaluator<nil::marshalling::field_type<Endianness>, PolysEvaluator>& filled_polys_evaluator
                ) {
                    using nil::marshalling::types::make_size_t;
                    using nil::marshalling::types::make_std_map;
                    using nil::marshalling::types::standard_array_list;
                    using nil::marshalling::types::make_standard_array_list;

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using polynomial_type = typename PolysEvaluator::polynomial_type;
                    using value_type = typename polynomial_type::value_type;

                    using size_t_marshalling_type = nil::marshalling::types::integral<TTypeBase, std::size_t>;
                    using polynomial_vector_marshalling_type = polynomial_vector<TTypeBase, polynomial_type>;
                    
                    using field_element_vector_type = field_element_vector<value_type, nil::marshalling::field_type<Endianness>>;
                    using array_of_field_element_vector_type = standard_array_list<TTypeBase, field_element_vector_type>;


                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using polynomial_type = typename PolysEvaluator::polynomial_type;
                    using value_type = typename polynomial_type::value_type;

                    PolysEvaluator result;
                    result._polys = make_std_map<TTypeBase, std::size_t, std::vector<polynomial_type>, size_t_marshalling_type, polynomial_vector_marshalling_type>(
                        std::get<0>(filled_polys_evaluator.value()), 
                        std::get<1>(filled_polys_evaluator.value()), 
                        make_size_t<TTypeBase>,
                        make_polynomial_vector<Endianness, polynomial_type>);

                    result._locked = make_std_map<TTypeBase, std::size_t, bool, size_t_marshalling_type, size_t_marshalling_type>(
                        std::get<2>(filled_polys_evaluator.value()), 
                        std::get<3>(filled_polys_evaluator.value()), 
                        make_size_t<TTypeBase>,
                        make_size_t<TTypeBase>);

                    result._points = make_std_map<TTypeBase, std::size_t, std::vector<std::vector<value_type>>, size_t_marshalling_type, array_of_field_element_vector_type>(
                        std::get<4>(filled_polys_evaluator.value()), 
                        std::get<5>(filled_polys_evaluator.value()), 
                        make_size_t<TTypeBase>,
                        [](const array_of_field_element_vector_type& points) -> std::vector<std::vector<value_type>> {
                            return make_standard_array_list<TTypeBase, std::vector<value_type>, field_element_vector_type>(
                                points, make_field_element_vector<value_type, Endianness>);
                        });

                    result._z = make_eval_storage<Endianness, typename PolysEvaluator::eval_storage_type>(
                        std::get<6>(filled_polys_evaluator.value()));

                    // We need to build _points_map, which duplicates the data in _points but as a map.
                    result.build_points_map();

                    return result;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_POLYS_EVALUATOR_HPP
