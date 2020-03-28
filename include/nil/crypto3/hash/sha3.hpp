//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_SHA3_HPP
#define CRYPTO3_HASH_SHA3_HPP

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/hash_stream_processor.hpp>
#include <nil/crypto3/hash/detail/sha3/sha3_functions.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @brief
             * @tparam DigestBits
             * @ingroup hash
             */
            template<std::size_t DigestBits>
            using sha3_compressor = keccak_1600_compressor<DigestBits>;

            template<std::size_t DigestBits = 512>
            class sha3 {
                typedef detail::sha3_functions<DigestBits> policy_type;

            public:
                struct construction {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit digest_endian;

                        constexpr static const std::size_t length_bits = 0;
                        constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                    };

                    typedef sponge_construction<params_type, typename policy_type::iv_generator,
                                                sha3_compressor<DigestBits>>
                        type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        typedef typename stream_endian::little_octet_big_bit endian;

                        constexpr static const std::size_t length_bits = construction::params_type::length_bits;
                        constexpr static const std::size_t value_bits = ValueBits;
                    };
                    typedef hash_stream_processor<construction, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = policy_type::digest_bits;
                typedef typename policy_type::digest_type digest_type;
            };
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif
