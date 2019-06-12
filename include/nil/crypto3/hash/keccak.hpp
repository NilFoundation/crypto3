//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_KECCAK_H_
#define CRYPTO3_KECCAK_H_

#include <string>

#include <nil/crypto3/hash/detail/keccak/keccak_functions.hpp>
#include <nil/crypto3/hash/detail/sponge_state_preprocessor.hpp>
#include <nil/crypto3/hash/detail/sponge_construction.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t DigestBits = 512>
            class keccak_1600_compressor {
                typedef detail::keccak_1600_functions<DigestBits> policy_type;
            public:

            };

            template<std::size_t DigestBits = 512>
            class keccak_1600 {
                typedef detail::keccak_1600_functions<DigestBits> policy_type;
            public:
                typedef sponge_construction<stream_endian::little_octet_big_bit, policy_type::digest_bits,
                                            typename policy_type::iv_generator,
                                            keccak_1600_compressor<DigestBits>> block_hash_type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                typedef block_hash_type_ block_hash_type;
#else
                struct block_hash_type : block_hash_type_ {
                };
#endif
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    typedef sponge_state_preprocessor<block_hash_type, StateAccumulator,
                                                      stream_endian::little_octet_big_bit, ValueBits,
                                                      0 // No length padding!
                                                     > type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };
                typedef typename block_hash_type::digest_type digest_type;
            };
        }

    }
}

#endif
