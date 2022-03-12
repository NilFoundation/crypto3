//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ALGEBRA_INFERENCE_TYPE_TRAITS_HPP
#define CRYPTO3_MARSHALLING_ALGEBRA_INFERENCE_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/crypto3/algebra/type_traits.hpp>

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

        template<typename T, typename Enabled>
        class is_compatible;

        template<typename T>
        class is_compatible <T, typename std::enable_if<nil::crypto3::algebra::is_group_element<T>::value>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename nil::crypto3::marshalling::types::curve_element<field_type<TEndian>,
                typename T::group_type>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

        template<typename T>
        class is_compatible <T, typename std::enable_if<nil::crypto3::algebra::is_field_element<T>::value>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = nil::crypto3::marshalling::types::field_element<
                nil::marshalling::field_type<TEndian>,
                T>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

    }        // namespace marshalling
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ALGEBRA_INFERENCE_TYPE_TRAITS_HPP