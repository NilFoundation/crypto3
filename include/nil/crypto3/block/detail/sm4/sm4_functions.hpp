//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SM4_FUNCTIONS_CPP_HPP
#define CRYPTO3_SM4_FUNCTIONS_CPP_HPP

#include <nil/crypto3/block/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<std::size_t WordBits>
                struct sm4_functions : public basic_functions<WordBits> {
                    typedef typename basic_functions<WordBits>::byte_type byte_type;
                    typedef typename basic_functions<WordBits>::word_type word_type;

                    constexpr static const std::size_t constants_size = 256;
                    typedef std::array<byte_type, constants_size> constants_type;
                    typedef std::array<word_type, constants_size> transposed_constants_type;

                    inline static word_type t_slow(word_type b, const constants_type &constants) {
                        const word_type t = basic_functions<WordBits>::make_uint_t<32>(
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 0)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 1)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 2)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 3)]);

                        // L linear transform
                        return t ^ (basic_functions<WordBits>::rotl<2>(t)) ^ basic_functions<WordBits>::rotl<10>(t) ^
                               basic_functions<WordBits>::rotl<18>(t) ^ basic_functions<WordBits>::rotl<24>(t);
                    }

                    inline static word_type t(word_type b, const transposed_constants_type &constants) {
                        return constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 0)] ^
                               (basic_functions<WordBits>::rotr<8>(
                                       constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 1)])) ^
                               basic_functions<WordBits>::rotr<16>(
                                       constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 2)]) ^
                               basic_functions<WordBits>::rotr<24>(
                                       constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 3)]);
                    }

// Variant of T for key round_constants_words
                    inline static word_type tp(word_type b, const constants_type &constants) {
                        const uint32_t t = basic_functions<WordBits>::make_uint_t<32>(
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 0)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 1)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 2)],
                                constants[basic_functions<WordBits>::extract_uint_t<CHAR_BIT>(b, 3)]);

                        // L' linear transform
                        return t ^ (basic_functions<WordBits>::rotl<13>(t)) ^ basic_functions<WordBits>::rotl<23>(t);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SM4_FUNCTIONS_CPP_HPP
