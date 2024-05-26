//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ALGEBRA_TYPE_TRAITS_HPP
#define CRYPTO3_MARSHALLING_ALGEBRA_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/marshalling/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
                class curve_element;

                template<typename TTypeBase, typename FieldValueType, typename... TOptions>
                class extended_field_element;

                template<typename TTypeBase, typename FieldValueType, typename... TOptions>
                class pure_field_element;

                template<typename TTypeBase,
                         typename FieldValueType,
                         typename... TOptions>
                using field_element =
                    typename std::conditional<algebra::is_extended_field_element<FieldValueType>::value,
                                              extended_field_element<TTypeBase, FieldValueType, TOptions...>,
                                              pure_field_element<TTypeBase, FieldValueType, TOptions...>>::type;
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
    namespace marshalling {

        /// @brief Compile time check function of whether a provided type is any
        ///     variant of nil::crypto3::marshalling::types::curve_element.
        /// @tparam T Any type.
        /// @return true in case provided type is any variant of @ref curve_element
        /// @related nil::crypto3::marshalling::types::curve_element
        template<typename T>
        struct is_curve_element {

            static const bool value = false;
        };

        template<typename TTypeBase, typename CurveGroupType, typename... TOptions>
        struct is_curve_element<nil::crypto3::marshalling::types::curve_element<TTypeBase, 
            CurveGroupType, TOptions...>> {

            static const bool value = true;
        };

        template<typename T>
        struct is_field_element {

            static const bool value = false;
        };

        template<typename TTypeBase, typename FieldValueType, typename... TOptions>
        struct is_field_element<nil::crypto3::marshalling::types::extended_field_element<TTypeBase, 
            FieldValueType, TOptions...>> {

            static const bool value = true;
        };

        template<typename TTypeBase, typename FieldValueType, typename... TOptions>
        struct is_field_element<nil::crypto3::marshalling::types::pure_field_element<TTypeBase, 
            FieldValueType, TOptions...>> {

            static const bool value = true;
        };

        template<typename T, typename Enabled>
        struct is_container;

        template<typename T>
        struct is_container <T, typename std::enable_if<is_curve_element<T>::value>::type> {
            static const bool value = false;
        };

        template<typename T>
        struct is_container <T, typename std::enable_if<is_field_element<T>::value>::type> {
            static const bool value = false;
        };

    }        // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ALGEBRA_TYPE_TRAITS_HPP