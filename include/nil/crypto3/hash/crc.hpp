//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_CRC_HPP
#define CRYPTO3_HASH_CRC_HPP

#include <boost/crc.hpp>
#include <boost/static_assert.hpp>

#include <nil/crypto3/hash/detail/primes.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>
#include <nil/crypto3/hash/detail/pack.hpp>

#include <climits>

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace hash {

// Boost.CRC undefs this, so re-define it
#define BOOST_CRC_PARM_TYPE  typename ::boost::uint_t<DigestBits>::fast

            template<unsigned DigestBits, BOOST_CRC_PARM_TYPE TruncPoly = 0u, BOOST_CRC_PARM_TYPE InitRem = 0u, BOOST_CRC_PARM_TYPE FinalXor = 0u, bool ReflectIn = false, bool ReflectRem = false>
            class basic_crc {
            public:
                typedef boost::crc_optimal<DigestBits, TruncPoly, InitRem, FinalXor, ReflectIn,
                                           ReflectRem> crc_computer;
                typedef typename crc_computer::value_type word_type;

                constexpr static const std::size_t value_bits = CHAR_BIT;
                typedef typename boost::uint_t<value_bits>::least value_type;

                BOOST_STATIC_ASSERT(DigestBits >= value_bits);

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef hash::static_digest<digest_bits> digest_type;

            public:
                basic_crc() {
                    reset();
                }

                void reset() {
                    crc_.reset();
                }

                digest_type digest() const {
                    word_type x = crc_.checksum();
                    digest_type d;
                    // TODO: Justify bit order
                    pack_n<stream_endian::big_bit, digest_bits, octet_bits>(&x, 1, d.data(), digest_bits / octet_bits);
                    return d;
                }

                digest_type end_message() {
                    digest_type d(std::move(digest()));
                    reset();
                    return d;
                }

            public:
                basic_crc &update_one(value_type x) {
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
                basic_crc &update_n(InputIterator p, size_t n) {
                    while (n--) {
                        update_one(*p++);
                    }
                    return *this;
                }

#ifndef CRYPTO3_HASH_NO_OPTIMIZATION

                template<typename ValT>
                basic_crc &update_n(ValT const *p, size_t n) {
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
                basic_crc &update_n(ValT *p, size_t n) {
                    return update_n((ValT const *) p, n);
                }

#endif

                template<typename InputIterator>
                basic_crc &update(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                basic_crc &update(InputIterator b, InputIterator e, Category) {
                    while (b != e) {
                        update_one(*b++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                basic_crc &update(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return update(b, e, cat());
                }

            private:
                crc_computer crc_;
            };

            /*!
             * @brief CRC. Non-cryptographically secure checksum.
             *
             * @ingroup hash
             *
             * @tparam Bits
             * @tparam TruncPoly
             * @tparam InitRem
             * @tparam FinalXor
             * @tparam ReflectIn
             * @tparam ReflectRem
             */
            template<unsigned DigestBits, BOOST_CRC_PARM_TYPE TruncPoly = 0u, BOOST_CRC_PARM_TYPE InitRem = 0u, BOOST_CRC_PARM_TYPE FinalXor = 0u, bool ReflectIn = false, bool ReflectRem = false>
            class crc {
                typedef basic_crc<Bits, TruncPoly, InitRem, FinalXor, ReflectIn, ReflectRem> octet_hash_type;
            public:
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    BOOST_STATIC_ASSERT(ValueBits == CHAR_BIT);
                    typedef octet_hash_type type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };

                constexpr static const std::size_t digest_bits = DigestBits;
                typedef typename octet_hash_type::digest_type digest_type;
            };

// http://www.libpng.org/pub/png/spec/1.2/PNG-Structure.html#CRC-algorithm
            typedef crc<32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, true, true> crc32_png;

        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_CRC_HPP
