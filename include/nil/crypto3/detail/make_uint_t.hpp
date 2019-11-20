//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------///

#ifndef CRYPTO3_MAKE_UINT_T_HPP
#define CRYPTO3_MAKE_UINT_T_HPP

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

#pragma clang loop unroll(full)
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
