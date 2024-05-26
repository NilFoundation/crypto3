//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
// Copyright (c) 2022 Noam Y <@NoamDev>
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

#ifndef CRYPTO3_MARSHALLING_FAST_CURVE_ELEMENT_HPP
#define CRYPTO3_MARSHALLING_FAST_CURVE_ELEMENT_HPP

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

#include <nil/crypto3/marshalling/algebra/types/field_element.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {

                template<typename TTypeBase, typename CurveGroupType>
                using fast_curve_element = nil::marshalling::types::bundle<
                    TTypeBase,
                    std::tuple<
                        // X
                        field_element<TTypeBase, typename CurveGroupType::value_type::field_type::value_type>,
                        // Y
                        field_element<TTypeBase, typename CurveGroupType::value_type::field_type::value_type>,
                        // is_infinity
                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>
                    >>;

                template<typename CurveGroupType, typename Endianness>
                fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>
                    fill_fast_curve_element(const typename CurveGroupType::value_type &point) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using field_element_type =
                        field_element<TTypeBase, typename CurveGroupType::value_type::field_type::value_type>;
                    std::uint8_t is_infinity = point.is_zero();
                    auto affine_point = point.to_affine();

                    return fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>(
                        std::make_tuple(
                                        field_element_type(affine_point.X),
                                        field_element_type(affine_point.Y),
                                        nil::marshalling::types::integral<TTypeBase, std::uint8_t>(is_infinity)
                                        ));
                }

                template<typename CurveGroupType, typename Endianness>
                typename CurveGroupType::value_type make_fast_curve_element(
                    const fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>
                        &filled_curve_element) {
                    std::uint8_t is_infinity = std::get<2>(filled_curve_element.value()).value();
                    if(is_infinity) {
                        return typename CurveGroupType::value_type();
                    }
                    return typename CurveGroupType::value_type(std::move(std::get<0>(filled_curve_element.value()).value()),
                                     std::move(std::get<1>(filled_curve_element.value()).value()),
                                     CurveGroupType::value_type::field_type::value_type::one());
                }

                template<typename CurveGroupType, typename Endianness>
                nil::marshalling::types::array_list<
                    nil::marshalling::field_type<Endianness>,
                    fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>,
                    nil::marshalling::option::sequence_size_field_prefix<
                        nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                    fill_fast_curve_element_vector(
                        const std::vector<typename CurveGroupType::value_type> &curve_elem_vector) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    using fast_curve_element_type = fast_curve_element<TTypeBase, CurveGroupType>;

                    using fast_curve_element_vector_type = nil::marshalling::types::array_list<
                        TTypeBase,
                        fast_curve_element_type,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>;

                    fast_curve_element_vector_type result;

                    std::vector<fast_curve_element_type> &val = result.value();
                    for (std::size_t i = 0; i < curve_elem_vector.size(); i++) {
                        val.push_back(fill_fast_curve_element<CurveGroupType, Endianness>(curve_elem_vector[i]));
                    }
                    return result;
                }

                template<typename CurveGroupType, typename Endianness>
                std::vector<typename CurveGroupType::value_type> make_fast_curve_element_vector(
                    const nil::marshalling::types::array_list<
                        nil::marshalling::field_type<Endianness>,
                        fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>,
                        nil::marshalling::option::sequence_size_field_prefix<
                            nil::marshalling::types::integral<nil::marshalling::field_type<Endianness>, std::size_t>>>
                        &curve_elem_vector) {

                    std::vector<typename CurveGroupType::value_type> result;
                    const std::vector<fast_curve_element<nil::marshalling::field_type<Endianness>, CurveGroupType>> &values =
                        curve_elem_vector.value();
                    std::size_t size = values.size();

                    for (std::size_t i = 0; i < size; i++) {
                        result.push_back(
                            make_fast_curve_element<CurveGroupType, Endianness>(values[i])
                        );
                    }
                    return result;
                }

            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_MARSHALLING_FAST_CURVE_ELEMENT_HPP
