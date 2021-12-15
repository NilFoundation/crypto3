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

#ifndef MARSHALLING_INFERENCE_TYPE_TRAITS_HPP
#define MARSHALLING_INFERENCE_TYPE_TRAITS_HPP

#include <boost/type_traits.hpp>
#include <boost/type_traits/is_same.hpp>

#include <nil/marshalling/field_type.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/float_value.hpp>
#include <nil/marshalling/types/array_list.hpp>

namespace nil {
    namespace marshalling {

        template<typename T, typename Enabled = void>
        class is_compatible;

        template<typename T>
        class is_compatible <T, typename std::enable_if<std::is_integral<T>::value>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename types::integral<field_type<TEndian>, T>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

        template<typename T>
        class is_compatible <T, typename std::enable_if<std::is_floating_point<T>::value>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename types::float_value<field_type<TEndian>, T>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

        template<typename T>
        class is_compatible <std::vector<T>, typename std::enable_if<is_compatible<T>::value
                                                                    && is_compatible<T>::fixed_size>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename types::array_list<
                field_type<TEndian>,
                typename is_compatible<T>::template type<TEndian>>;
            static const bool value = true;
            static const bool fixed_size = false;
        };

        template<typename T, std::size_t TSize>
        class is_compatible <std::array<T, TSize>, typename std::enable_if<is_compatible<T>::value
                                                                          && is_compatible<T>::fixed_size>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename types::array_list<
                field_type<TEndian>,
                typename is_compatible<T>::template type<TEndian>,
                option::fixed_size_storage<TSize>>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

        template<typename T, std::size_t TSize>
        class is_compatible <boost::array<T, TSize>, typename std::enable_if<is_compatible<T>::value
                                                                          && is_compatible<T>::fixed_size>::type> {
            using default_endianness = option::big_endian;
        public:
            template <typename TEndian = default_endianness>
            using type = typename types::array_list<
                field_type<TEndian>,
                typename is_compatible<T>::template type<TEndian>,
                option::fixed_size_storage<TSize>>;
            static const bool value = true;
            static const bool fixed_size = true;
        };

    }        // namespace marshalling
}    // namespace nil

#endif    // MARSHALLING_INFERENCE_TYPE_TRAITS_HPP