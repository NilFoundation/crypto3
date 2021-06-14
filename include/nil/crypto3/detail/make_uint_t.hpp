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
//---------------------------------------------------------------------------///

#ifndef CRYPTO3_MAKE_UINT_T_HPP
#define CRYPTO3_MAKE_UINT_T_HPP

#include <tuple>

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<std::size_t Size, typename Integer>
            static inline typename boost::uint_t<Size>::exact extract_uint_t(Integer v, std::size_t position) {
                return static_cast<typename boost::uint_t<Size>::exact>(v >>
                                                                        (((~position) & (sizeof(Integer) - 1)) << 3));
            }

            template<std::size_t Size, typename T>
            static inline typename boost::uint_t<Size>::exact make_uint_t(const std::initializer_list<T> &args) {
                typedef typename std::initializer_list<T>::value_type value_type;
                typename boost::uint_t<Size>::exact result = 0;


                for (const value_type &itr : args) {
                    result = static_cast<typename boost::uint_t<Size>::exact>(
                        (result << std::numeric_limits<value_type>::digits) | itr);
                }

                return result;
            }

            template<std::size_t Size, typename... Args>
            static inline typename boost::uint_t<Size>::exact make_uint_t(Args... args) {
                return make_uint_t<Size, typename std::tuple_element<0, std::tuple<Args...>>::type>({args...});
            }
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAKE_UINT_T_HPP
