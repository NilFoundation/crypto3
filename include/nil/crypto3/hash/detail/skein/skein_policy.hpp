//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SKEIN_POLICY_HPP
#define CRYPTO3_SKEIN_POLICY_HPP

#include <nil/crypto3/detail/basic_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<std::size_t DigestBits>
                struct skein_policy : public ::nil::crypto3::detail::basic_functions<64> {
                    typedef typename block::threefish<DigestBits> block_cipher_type;

                    constexpr static const std::size_t digest_bits = DigestBits;
                    typedef static_digest<digest_bits> digest_type;

                    constexpr static const std::size_t block_bits = block_cipher_type::block_bits;
                    constexpr static const std::size_t block_words = block_cipher_type::block_words;
                    typedef typename block_cipher_type::block_type block_type;

                    constexpr static const std::size_t state_bits = block_bits;
                    constexpr static const std::size_t state_words = block_words;
                    typedef block_type state_type;

                    struct iv_generator {
                        state_type const &operator()() const {
                            constexpr static const state_type H0 = {0x00};
                            return H0;
                        }
                    };
                };
            }
        }
    }
}

#endif //CRYPTO3_SKEIN_POLICY_HPP
