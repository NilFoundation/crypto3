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

#include <nil/crypto3/utilities/loadstore.hpp>

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
                        const word_type t = make_uint32(constants[get_byte(0, b)], constants[get_byte(1, b)],
                                constants[get_byte(2, b)], constants[get_byte(3, b)]);

                        // L linear transform
                        return t ^ rotl<2>(t) ^ rotl<10>(t) ^ rotl<18>(t) ^ rotl<24>(t);
                    }

                    inline static word_type t(word_type b, const transposed_constants_type &constants) {
                        return constants[get_byte(0, b)] ^ rotr<8>(constants[get_byte(1, b)]) ^
                               rotr<16>(constants[get_byte(2, b)]) ^ rotr<24>(constants[get_byte(3, b)]);
                    }

// Variant of T for key round_constants_words
                    inline static word_type tp(word_type b, const constants_type &constants) {
                        const uint32_t t = make_uint32(constants[get_byte(0, b)], constants[get_byte(1, b)],
                                constants[get_byte(2, b)], constants[get_byte(3, b)]);

                        // L' linear transform
                        return t ^ rotl<13>(t) ^ rotl<23>(t);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_SM4_FUNCTIONS_CPP_HPP
