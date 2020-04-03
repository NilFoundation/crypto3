//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM4_FUNCTIONS_CPP_HPP
#define CRYPTO3_SM4_FUNCTIONS_CPP_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct sm4_functions : public ::nil::crypto3::detail::basic_functions<WordBits> {
                    typedef ::nil::crypto3::detail::basic_functions<WordBits> policy_type;
                    typedef typename policy_type::word_type word_type;

                    typedef typename policy_type::byte_type byte_type;

                    constexpr static const std::size_t constants_size = 256;
                    typedef std::array<byte_type, constants_size> constants_type;
                    typedef std::array<word_type, constants_size> transposed_constants_type;

                    inline static word_type t_slow(word_type b, const constants_type &constants) {
                        const word_type t = ::nil::crypto3::detail::make_uint_t<WordBits>(
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 0)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 1)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 2)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 3)]);

                        // L linear transform
                        return t ^ (policy_type::template rotl<2>(t)) ^
                               policy_type::template rotl<10>(t) ^
                               policy_type::template rotl<18>(t) ^
                               policy_type::template rotl<24>(t);
                    }

                    inline static word_type t(word_type b, const transposed_constants_type &constants) {
                        return constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 0)] ^
                               (policy_type::template rotr<8>(
                                   constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 1)])) ^
                               policy_type::template rotr<16>(
                                   constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 2)]) ^
                               policy_type::template rotr<24>(
                                   constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 3)]);
                    }

                    // Variant of T for key round_constants_words
                    inline static word_type tp(word_type b, const constants_type &constants) {
                        const word_type t = ::nil::crypto3::detail::make_uint_t<WordBits>(
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 0)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 1)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 2)],
                            constants[::nil::crypto3::detail::extract_uint_t<CHAR_BIT>(b, 3)]);

                        // L' linear transform
                        return t ^ (policy_type::template rotl<13>(t)) ^
                               policy_type::template rotl<23>(t);
                    }
                };
            }    // namespace detail
        }        // namespace block
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_SM4_FUNCTIONS_CPP_HPP
