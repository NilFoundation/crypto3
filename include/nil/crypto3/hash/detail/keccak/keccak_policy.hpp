//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KECCAK_POLICY_HPP
#define CRYPTO3_KECCAK_POLICY_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct keccak_1600_policy : public ::nil::crypto3::detail::basic_functions<64> {

                    constexpr static const std::size_t digest_bits = DigestBits; 
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t state_bits = 1600;
                    constexpr static const std::size_t state_words = state_bits / word_bits;
                    typedef typename std::array<word_type, state_words> state_type;
 
                    constexpr static const std::size_t block_bits = state_bits - 2 * digest_bits;
                    constexpr static const std::size_t block_words = block_bits / word_bits;
                    typedef std::array<word_type, block_words> block_type;

                    constexpr static const std::size_t length_bits = 0;

                    typedef typename stream_endian::big_octet_little_bit digest_endian;

                    constexpr static const std::size_t rounds = 24;

                    struct iv_generator {
                        state_type const &operator()() const {
                            static state_type const H0 = {
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), 
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                            UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000),
                            UINT64_C(0x0000000000000000)};
                            return H0;
                        }
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_KECCAK_POLICY_HPP
