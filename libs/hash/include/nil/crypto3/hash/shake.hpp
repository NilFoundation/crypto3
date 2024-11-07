//---------------------------------------------------------------------------//
// Copyright (c) 2024 Valeh Farzaliyev <estoniaa@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_SHA3_HPP
#define CRYPTO3_HASH_SHA3_HPP

#include <nil/crypto3/hash/accumulators/hash.hpp>
#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/shake/shake_functions.hpp>
#include <nil/crypto3/hash/detail/shake/shake_policy.hpp>
#include <nil/crypto3/hash/detail/shake/shake_padding.hpp>
#include <nil/crypto3/hash/detail/sponge_construction.hpp>
#include <nil/crypto3/hash/detail/stream_processors/stream_processors_enum.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            /*!
             * @brief
             * @tparam DigestBits
             * @ingroup hashes
             */
            template<std::size_t HalfCapacity, std::size_t DigestBits>
            class shake {
            public:
                typedef detail::shake_functions<HalfCapacity> policy_type;

                constexpr static const std::size_t word_bits = policy_type::word_bits;
                typedef typename policy_type::word_type word_type;

                constexpr static const std::size_t block_bits = policy_type::block_bits;
                constexpr static const std::size_t block_words = policy_type::block_words;
                typedef typename policy_type::block_type block_type;

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef static_digest<DigestBits> digest_type;

                constexpr static const std::size_t pkcs_id_size = policy_type::pkcs_id_size;
                constexpr static const std::size_t pkcs_id_bits = policy_type::pkcs_id_bits;
                typedef typename policy_type::pkcs_id_type pkcs_id_type;

                constexpr static const pkcs_id_type pkcs_id = policy_type::pkcs_id;

                struct construction {
                    struct params_type {
                        typedef typename policy_type::digest_endian digest_endian;

                        constexpr static const std::size_t length_bits = policy_type::length_bits;
                        constexpr static const std::size_t digest_bits = DigestBits;
                    };

                    typedef sponge_construction<params_type, policy_type, typename policy_type::iv_generator,
                                                detail::shake_functions<HalfCapacity>, detail::shake_functions<HalfCapacity>, detail::shake_padder<policy_type>>
                        type;
                };

                constexpr static detail::stream_processor_type stream_processor = detail::stream_processor_type::Block;
                using accumulator_tag = accumulators::tag::hash<shake<HalfCapacity, DigestBits>>;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif
