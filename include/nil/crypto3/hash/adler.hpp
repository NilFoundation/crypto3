//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_ADLER_HPP
#define CRYPTO3_HASH_ADLER_HPP

#include <array>

#include <nil/crypto3/hash/detail/primes.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>
#include <nil/crypto3/hash/detail/pack.hpp>

#include <boost/static_assert.hpp>

#ifdef CRYPTO3_HASH_SHOW_PROGRESS
#include <cstdio>
#endif

namespace nil {
    namespace crypto3 {
        namespace hash {
            template<std::size_t Bits>
            class basic_adler {
            public:
                constexpr static const std::size_t value_bits = 8;
                typedef typename boost::uint_t<value_bits>::least value_type;

                BOOST_STATIC_ASSERT(Bits % 2 == 0);
                BOOST_STATIC_ASSERT(Bits >= value_bits);

                constexpr static const std::size_t digest_bits = Bits;
                typedef hash::static_digest<digest_bits> digest_type;

                constexpr static const std::size_t word_bits = Bits;
                typedef typename boost::uint_t<word_bits>::least word_type;

                typedef std::array<word_type, 2> state_type;

                static word_type const modulo = detail::largest_prime<Bits / 2>::value;

            public:
                basic_adler() {
                    reset();
                }

                void reset() {
                    state_[0] = 0;
                    state_[1] = 1;
                }

                digest_type digest() const {
                    word_type x = (state_[0] << (Bits / 2)) | state_[1];
                    digest_type d;
                    // RFC 1950, Section 2.2 stores the ADLER-32 in big-endian
                    pack_n<stream_endian::big_bit, digest_bits, octet_bits>(&x, 1, d.data(), digest_bits / octet_bits);
                    return d;
                }

                digest_type end_message() {
                    digest_type d(std::move(digest()));
                    reset();
                    return d;
                }

            public:

                basic_adler &update_one(value_type x) {
                    if (Bits < 16) {
                        x %= modulo;
                    } // avoid overflow
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                    printf("(%.4x, %.4x) + %.2x ==> ", (int)state_[0], (int)state_[1], (int)x);
#endif
                    state_[1] = (state_[1] + x) % modulo;
                    state_[0] = (state_[0] + state_[1]) % modulo;
#ifdef CRYPTO3_HASH_SHOW_PROGRESS
                    printf("(%.4x, %.4x) mod %.4x\n", (int)state_[0], (int)state_[1], (int)modulo);
#endif
                    return *this;
                }

                template<typename InputIterator>
                basic_adler &update_n(InputIterator p, size_t n) {
#ifndef CRYPTO3_HASH_NO_OPTIMIZATION

                    unsigned const fast_word_bits = (word_bits < 16 ? 16 : word_bits);
                    typedef typename boost::uint_t<fast_word_bits>::least/*fast*/ fast_word_type;
/*

Worst-case behaviour for delaying the modulo:
- every input is 255
- s1 and s0 start out at modulo-1

So after k inputs, we have:
- s1 = (modulo-1) + k*255
- s0 = (modulo-1) + Sigma(i = 1 to k)[ (modulo-1) + i*255 ]
     = (modulo-1) + k*(modulo-1) + Sigma(i = 1 to k)[ i*255 ]
     = (k+1)*(modulo-1) + 255 * Sigma(i = 1 to k)[i]
     = (k+1)*(modulo-1) + 255 * k*(k+1)/2

And to avoid overflow we need s1, s0 <= 2**fast_word_bits - 1

s1 = (modulo-1) + k*255 <= 2**fast_word_bits - 1
     k*255 <= 2**fast_word_bits - 1 - (modulo-1)
     k <= (2**fast_word_bits - modulo)/255

Then use an overestimate for s0 to make the numbers nicer
s0 < (k+1)*modulo + 256/2(k+1)**2 < 2**fast_word_bits

Which solves as
k < ( sqrt(512*2**fast_word_bits + modulo**2) - m - 256 )/256

So then overestimating m as 2**(word_bits/2) and other safe approximations gives
k < 2**((fast_word_bits-7)/2) - 2**((word_bits-16)/2) - 1

Bits    Limit
----    -----
8       16
16      16
24      240
32      3840
40      61440
48      983040
56      15728640
64      251658240

*/

                    unsigned const less = (1 << (fast_word_bits / 2 - 8));
                    unsigned const limit = (1 << (fast_word_bits / 2 - 4)) - (word_bits < 16 ? 0 : less);

#define CRYPTO3_HASH_ADLER_STEP \
        { value_type x = *p++; s1 += x; s0 += s1; }

#define CRYPTO3_HASH_ADLER_8_STEPS \
        { \
            CRYPTO3_HASH_ADLER_STEP CRYPTO3_HASH_ADLER_STEP \
            CRYPTO3_HASH_ADLER_STEP CRYPTO3_HASH_ADLER_STEP \
            CRYPTO3_HASH_ADLER_STEP CRYPTO3_HASH_ADLER_STEP \
            CRYPTO3_HASH_ADLER_STEP CRYPTO3_HASH_ADLER_STEP \
        }

                    fast_word_type s0 = state_[0];
                    fast_word_type s1 = state_[1];

                    for (; n >= limit; n -= limit) {
                        unsigned m = limit;
                        for (; m >= 8; m -= 8) {
                            CRYPTO3_HASH_ADLER_8_STEPS
                        }
                        while (m--) {
                            CRYPTO3_HASH_ADLER_STEP
                        }
                        s1 %= modulo;
                        s0 %= modulo;
                    }
                    for (; n >= 8; n -= 8) {
                        CRYPTO3_HASH_ADLER_8_STEPS
                    }
                    while (n--) {
                        CRYPTO3_HASH_ADLER_STEP
                    }
                    s1 %= modulo;
                    s0 %= modulo;

                    state_[0] = s0;
                    state_[1] = s1;

#else
                    while (n--) update_one(*p++);
#endif
                    return *this;
                }

                template<typename InputIterator>
                basic_adler &update(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                basic_adler &update(InputIterator b, InputIterator e, Category) {
                    while (b != e) {
                        update_one(*b++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                basic_adler &update(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return update(b, e, cat());
                }

            private:
                state_type state_;
            };

            /*!
             * @brief Adler. Non-cryptographically secure checksum. Adler32
             * checksum is used in the zlib format. 32 bit output.
             * @ingroup hash
             * @tparam Bit
             * s
             */
            template<unsigned Bits>
            struct adler {
            private:
                typedef basic_adler<Bits> octet_hash_type;
            public:
                template<typename StateAccumulator, std::size_t ValueBits>
                struct stream_processor {
                    struct params {

                    };

                    BOOST_STATIC_ASSERT(ValueBits == 8);
                    typedef octet_hash_type type_;
#ifdef CRYPTO3_HASH_NO_HIDE_INTERNAL_TYPES
                    typedef type_ type;
#else
                    struct type : type_ {
                    };
#endif
                };
                typedef typename octet_hash_type::digest_type digest_type;
            };

        }
    }
} // namespace nil

#endif // CRYPTO3_HASH_ADLER_HPP
