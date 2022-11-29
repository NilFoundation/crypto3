//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_CRC_HPP
#define CRYPTO3_HASH_CRC_HPP

#include <nil/crypto3/hash/detail/crc/accumulator.hpp>

#include <nil/crypto3/detail/primes.hpp>
#include <nil/crypto3/detail/static_digest.hpp>
#include <nil/crypto3/detail/pack.hpp>

#include <climits>

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace hashes {
            // Boost.CRC undefs this, so re-define it
#if !(defined(BOOST_NO_DEPENDENT_TYPES_IN_TEMPLATE_VALUE_PARAMETERS) || (defined(BOOST_MSVC) && (BOOST_MSVC <= 1300)))
#define BOOST_CRC_PARM_TYPE typename ::boost::uint_t<DigestBits>::fast
#else
#define BOOST_CRC_PARM_TYPE unsigned long
#endif

            template<typename Hash, typename StateAccumulator, typename Params>
            class crc_stream_processor {
            protected:
                typedef Hash construction_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

                typedef typename boost::uint_t<CHAR_BIT> byte_type;

                constexpr static const std::size_t word_bits = construction_type::word_bits;
                typedef typename construction_type::word_type word_type;

                constexpr static const std::size_t block_bits = construction_type::block_bits;
                constexpr static const std::size_t block_words = construction_type::block_words;
                typedef typename construction_type::block_type block_type;

            public:
                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;

                typedef typename construction_type::digest_type digest_type;

                crc_stream_processor(accumulator_type &a) : acc(a) {
                }

            protected:
                crc_stream_processor &update_one(value_type value) {
                    acc(value);
                    return *this;
                }

                template<typename InputIterator>
                crc_stream_processor &update_n(InputIterator p, size_t n) {
                    acc(p, accumulators::bits =
                               n * sizeof(typename std::iterator_traits<InputIterator>::value_type) * CHAR_BIT);
                    return *this;
                }

            public:
                template<typename InputIterator>
                inline crc_stream_processor &operator()(InputIterator b, InputIterator e,
                                                        std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                inline crc_stream_processor &operator()(InputIterator first, InputIterator last, Category) {
                    while (first != last) {
                        update_one(*first++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                inline crc_stream_processor &operator()(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return operator()(b, e, cat());
                }

                template<typename ContainerT>
                inline crc_stream_processor &operator()(const ContainerT &c) {
                    return update_n(c.data(), c.size());
                }

            protected:
                accumulator_type &acc;
            };

            template<unsigned DigestBits, BOOST_CRC_PARM_TYPE TruncPoly = 0u, BOOST_CRC_PARM_TYPE InitRem = 0u,
                     BOOST_CRC_PARM_TYPE FinalXor = 0u, bool ReflectIn = false, bool ReflectRem = false>
            class basic_crc {
            public:
                typedef boost::crc_optimal<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem>
                    crc_computer;

                constexpr static const std::size_t word_bits = DigestBits;
                typedef typename crc_computer::value_type word_type;

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef static_digest<digest_bits> digest_type;

                constexpr static const std::size_t state_bits = digest_bits;
                constexpr static const std::size_t state_words = digest_bits / word_bits;
                typedef digest_type state_type;

                constexpr static const std::size_t block_bits = DigestBits;
                constexpr static const std::size_t block_words = block_bits / word_bits;
                typedef state_type block_type;

                constexpr static const std::size_t value_bits = CHAR_BIT;
                typedef typename boost::uint_t<value_bits>::least value_type;

                BOOST_STATIC_ASSERT(DigestBits >= value_bits);

            public:
                basic_crc() {
                    reset();
                }

                inline void reset() {
                    crc_.reset();
                }

                digest_type digest() const {
                    using namespace ::nil::crypto3::detail;

                    word_type x = crc_.checksum();
                    digest_type d;
                    // TODO: Justify bit order
                    pack_n<stream_endian::big_bit, stream_endian::big_bit, digest_bits, octet_bits>(
                        &x, 1, d.data(), digest_bits / octet_bits);
                    return d;
                }

                digest_type end_message() {
                    digest_type d(std::move(digest()));
                    reset();
                    return d;
                }

            protected:
                inline basic_crc &update_one(value_type x) {
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                    printf("%.8lx + %.2x ==> ", (long)crc_.checksum(), (int)x);
#endif
                    crc_.process_byte(x);
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                    printf("%.8lx\n", (long)crc_.checksum());
#endif
                    return *this;
                }

                template<typename InputIterator>
                inline basic_crc &update_n(InputIterator p, size_t n) {
                    while (n--) {
                        update_one(*p++);
                    }
                    return *this;
                }

#ifndef CRYPTO3_HASH_NO_OPTIMIZATION

                template<typename ValT>
                inline basic_crc &update_n(ValT const *p, size_t n) {
                    if (sizeof(ValT) == 1) {
                        crc_.process_bytes(p, n);
                    } else {
                        while (n--) {
                            update_one(*p++);
                        }
                    }
                    return *this;
                }

                template<typename ValT>
                inline basic_crc &update_n(ValT *p, size_t n) {
                    return update_n((ValT const *)p, n);
                }

#endif
            public:
                inline basic_crc &operator()(value_type v) {
                    return update_one(v);
                }

                template<typename InputIterator>
                inline basic_crc &operator()(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                inline basic_crc &operator()(InputIterator b, InputIterator e, Category) {
                    while (b != e) {
                        update_one(*b++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                inline basic_crc &operator()(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return operator()(b, e, cat());
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
                struct construction {
                    struct params_type { };
                    typedef basic_crc<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem> type;
                };

                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params_type {
                        constexpr static const std::size_t digest_bits = DigestBits;
                        constexpr static const std::size_t value_bits = ValueBits;
                    };

                    BOOST_STATIC_ASSERT(ValueBits == CHAR_BIT);
                    typedef crc_stream_processor<typename construction::type, StateAccumulator, params_type> type;
                };

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef typename construction::type::digest_type digest_type;
            };

            // http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html#CRC-algorithm
            typedef crc<32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32_png;

        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_CRC_HPP
