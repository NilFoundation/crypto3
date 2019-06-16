//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_SHA1_HPP
#define CRYPTO3_HASH_SHA1_HPP

#include <nil/crypto3/block/shacal1.hpp>

#include <nil/crypto3/hash/detail/davies_meyer_compressor.hpp>
#include <nil/crypto3/hash/detail/sha1_policy.hpp>
#include <nil/crypto3/hash/detail/state_adder.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_construction.hpp>
#include <nil/crypto3/hash/detail/merkle_damgard_state_preprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {

            /*!
             * @brief SHA1. Widely adopted NSA designed hash function. Starting
             * to show significant signs of weakness, and collisions can now be
             * generated. Avoid in new designs.
             * @ingroup hash
             */
            class sha1 {
                typedef detail::sha1_policy policy_type;
                typedef block::shacal1 block_cipher_type;
            public:
                typedef merkle_damgard_construction<stream_endian::big_octet_big_bit, policy_type::digest_bits,
                                                    policy_type::iv_generator,
                                                    davies_meyer_compressor<block_cipher_type,
                                                                            detail::state_adder>> construction_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef construction_type_ construction_type;
#else
                struct construction_type : construction_type_ {
                };
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::big_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = construction_type::word_bits * 2;
                    };

                    typedef merkle_damgard_state_preprocessor<construction_type, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename construction_type::digest_type digest_type;
            };

        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_SHA1_HPP
