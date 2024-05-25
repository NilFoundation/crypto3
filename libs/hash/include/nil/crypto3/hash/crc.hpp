//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_CRC_HPP
#define CRYPTO3_HASH_CRC_HPP

#include <array>
#include <climits>

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
#include <cstdio>
#endif

#include <boost/crc.hpp>

#include <nil/crypto3/detail/basic_functions.hpp>
#include <nil/crypto3/detail/primes.hpp>
#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/hash/accumulators/hash.hpp>
#include <nil/crypto3/hash/detail/stream_processors/stream_processors_enum.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            // Boost.CRC undefs this, so re-define it
#if !(defined(BOOST_NO_DEPENDENT_TYPES_IN_TEMPLATE_VALUE_PARAMETERS) || (defined(BOOST_MSVC) && (BOOST_MSVC <= 1300)))
#define BOOST_CRC_PARM_TYPE typename ::boost::uint_t<DigestBits>::fast
#else
#define BOOST_CRC_PARM_TYPE unsigned long
#endif

            struct crc_policy {
                using basic_policy =  ::nil::crypto3::detail::basic_functions<8>;

                constexpr static const std::size_t word_bits = basic_policy::byte_bits;
                using word_type = basic_policy::byte_type;

                constexpr static const std::size_t block_bits = 64;
                constexpr static const std::size_t block_words = 8;
                using block_type = std::array<word_type, block_words>;

                using digest_endian = stream_endian::big_octet_big_bit;
            };

            template<unsigned DigestBits, BOOST_CRC_PARM_TYPE TruncPoly = 0u, BOOST_CRC_PARM_TYPE InitRem = 0u,
                     BOOST_CRC_PARM_TYPE FinalXor = 0u, bool ReflectIn = false, bool ReflectRem = false>
            class crc_construction {
            public:
                typedef boost::crc_optimal<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem>
                    crc_computer;
                constexpr static const std::size_t digest_bits = DigestBits;
                typedef static_digest<digest_bits> digest_type;

                constexpr static const std::size_t word_bits = crc_policy::word_bits;
                using word_type = crc_policy::word_type;

                constexpr static const std::size_t block_bits = crc_policy::block_bits;
                constexpr static const std::size_t block_words = crc_policy::block_words;
                using block_type = crc_policy::block_type;

                using digest_endian = crc_policy::digest_endian;

            public:
                crc_construction() {
                    reset();
                }

                void reset() {
                    crc_.reset();
                }

                digest_type digest(block_type block, std::size_t total_bits_seen) {
                    using namespace ::nil::crypto3::detail;

                    crc_.process_block(block.begin(), block.begin() + (total_bits_seen % block_bits) / word_bits);

                    auto x = crc_.checksum();
                    digest_type d;
                    pack_n<stream_endian::big_octet_big_bit, stream_endian::big_octet_big_bit, digest_bits, octet_bits>(&x, 1, d.begin());
                    return d;
                }
                crc_construction &process_block(const block_type &block) {
                    crc_.process_block(block.begin(), block.end());
                    return *this;
                }

            protected:
                crc_computer crc_;
            };

            /*!
             * @brief CRC. Non-cryptographically secure checksum.
             *
             * @ingroup hash
             *
             * @tparam DigestBits
             * @tparam TruncPoly
             * @tparam InitRem
             * @tparam FinalXor
             * @tparam ReflectIn
             * @tparam ReflectRem
             */
            template<std::size_t DigestBits, BOOST_CRC_PARM_TYPE TruncPoly = 0u, BOOST_CRC_PARM_TYPE InitRem = 0u,
                     BOOST_CRC_PARM_TYPE FinalXor = 0u, bool ReflectIn = false, bool ReflectRem = false>
            class crc {
            public:
                using policy_type = crc_policy;

                struct construction {
                    struct params_type {
                        using digest_endian = typename policy_type::digest_endian;

                        constexpr static const std::size_t length_bits = 64; // unused?
                        constexpr static const std::size_t digest_bits = DigestBits;
                    };
                    typedef crc_construction<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem> type;
                };

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef typename construction::type::digest_type digest_type;

                constexpr static detail::stream_processor_type stream_processor = detail::stream_processor_type::Block;
                using accumulator_tag = accumulators::tag::hash<crc<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem>>;
            };

            // http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html#CRC-algorithm
            typedef crc<32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32_png;

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_CRC_HPP
