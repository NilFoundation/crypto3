//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_FIELD_BASE_HPP
#define MARSHALLING_FIELD_BASE_HPP

#include <nil/marshalling/endianness.hpp>
#include <nil/marshalling/options.hpp>

namespace nil {
    namespace marshalling {
        namespace detail {

            template<typename... TOptions>
            class field_base;

            template<>
            class field_base<> {
            protected:
                // Use big endian by default
                using endian_type = nil::marshalling::endian::big_endian;

                // Use unsigned type by default for versioning
                using version_type = unsigned;
            };

            template<typename TEndian, typename... TOptions>
            class field_base<nil::marshalling::option::endian<TEndian>, TOptions...> : public field_base<TOptions...> {
            protected:
                using endian_type = TEndian;
            };

            template<typename T, typename... TOptions>
            class field_base<nil::marshalling::option::version_type<T>, TOptions...> : public field_base<TOptions...> {
            protected:
                using version_type = T;
            };

            template<typename... TOptions>
            class field_base<nil::marshalling::option::empty_option, TOptions...> : public field_base<TOptions...> { };

            template<typename... TTuple, typename... TOptions>
            class field_base<std::tuple<TTuple...>, TOptions...> : public field_base<TTuple..., TOptions...> { };

        }    // namespace detail
    }        // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_FIELD_BASE_HPP
