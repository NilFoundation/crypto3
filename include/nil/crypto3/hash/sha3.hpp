//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_SHA3_H_
#define CRYPTO3_SHA3_H_

#include <nil/crypto3/utilities/secmem.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/sponge_state_preprocessor.hpp>
#include <nil/crypto3/hash/detail/sha3_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits> using sha3_compressor = keccak_1600_compressor<DigestBits>;

            template<std::size_t DigestBits = 512>
            class sha3 {
                typedef detail::sha3_functions<DigestBits> policy_type;
            public:
                typedef sponge_construction<stream_endian::little_octet_big_bit, policy_type::digest_bits,
                                            typename policy_type::iv_generator,
                                            sha3_compressor<DigestBits>> block_hash_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef block_hash_type_ block_hash_type;
#else
                struct block_hash_type : block_hash_type_ {
                };
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t value_bits = ValueBits;
                        constexpr static const std::size_t length_bits = 0;
                    };
                    typedef sponge_state_preprocessor<block_hash_type, StateAccumulator, params_type> type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename block_hash_type::digest_type digest_type;
            };
        }
    }
}

#endif
