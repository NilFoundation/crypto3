/* boost random/chacha.hpp header file
 *
 * Copyright Mikhail Komarov 2020
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

//  See http://www.boost.org/libs/random for documentation.

#ifndef BOOST_RANDOM_CHACHA_HPP
#define BOOST_RANDOM_CHACHA_HPP

#include <string>
#include <boost/config.hpp>
#include <boost/noncopyable.hpp>
#include <boost/random/detail/auto_link.hpp>
#include <boost/system/config.hpp>    // force autolink to find Boost.System

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>

#include <nil/crypto3/mac/algorithm/compute.hpp>
#include <nil/crypto3/mac/hmac.hpp>

#include <nil/crypto3/stream/algorithm/encrypt.hpp>
#include <nil/crypto3/stream/chacha.hpp>

namespace boost {
    namespace random {

        /**
         * ChaCha_RNG is a very fast but completely ad-hoc RNG created by
         * creating a 256-bit random value and using it as a key for ChaCha20.
         *
         * The RNG maintains two 256-bit keys, one for HMAC_SHA256 (HK) and the
         * other for ChaCha20 (CK). To compute a new key in response to
         * reseeding request or add_entropy calls, ChaCha_RNG computes
         *   CK' = HMAC_SHA256(HK, input_material)
         * Then a new HK' is computed by running ChaCha20 with the new key to
         * output 32 bytes:
         *   HK' = ChaCha20(CK')
         *
         * Now output can be produced by continuing to produce output with ChaCha20
         * under CK'
         *
         * The first HK (before seeding occurs) is taken as the all zero value.
         *
         * @warning This RNG construction is probably fine but is non-standard.
         * The primary reason to use it is in cases where the other RNGs are
         * not fast enough.
         */

        template<typename StreamCipher = nil::crypto3::stream::chacha<64, 128, 20>,
                 typename MessageAuthenticationCode = nil::crypto3::mac::hmac<nil::crypto3::hashes::sha2<256>>>
        struct chacha : private noncopyable {
            typedef StreamCipher stream_cipher_type;
            typedef MessageAuthenticationCode mac_type;
            typedef typename mac_type::key_type key_type;

            typedef std::vector<std::uint8_t> result_type;

            BOOST_STATIC_CONSTANT(std::size_t, reseed_interval = 256);

            BOOST_STATIC_CONSTANT(bool, has_fixed_range = false);

            /** Returns the smallest value that the \random_device can produce. */
            static BOOST_CONSTEXPR std::size_t min BOOST_PREVENT_MACRO_SUBSTITUTION() {
                return 0;
            }
            /** Returns the largest value that the \random_device can produce. */
            static BOOST_CONSTEXPR std::size_t max BOOST_PREVENT_MACRO_SUBSTITUTION() {
                return ~0u;
            }

            /** Constructs a @c random_device, optionally using the default device. */
            BOOST_RANDOM_DECL chacha() : cnt(0) {
                mac_key.fill(0);
            }
            /**
             * Constructs a @c random_device, optionally using the given token as an
             * access specification (for example, a URL) to some implementation-defined
             * service for monitoring a stochastic process.
             */
            template<typename SeedSinglePassRange>
            BOOST_RANDOM_DECL explicit chacha(const SeedSinglePassRange &token) : cnt(0) {
                mac_key.fill(0);
            }

            BOOST_RANDOM_DECL ~chacha() {
                mac_key.fill(0);
                mac_key.clear();
            }

            /** default seeds the underlying generator. */
            void seed() {
                cnt = 0;
            }

            /** Seeds the underlying generator with first and last. */
            template<typename InputIterator>
            void seed(InputIterator &first, InputIterator last) {
                update(first, last);

                if (CHAR_BIT * std::distance(first, last) *
                        sizeof(typename std::iterator_traits<InputIterator>::value_type) >=
                    reseed_interval) {
                    cnt = 0;
                }
            }

            /**
             * Returns: An entropy estimate for the random numbers returned by
             * operator(), in the range min() to log2( max()+1). A deterministic
             * random number generator (e.g. a pseudo-random number engine)
             * has entropy 0.
             *
             * Throws: Nothing.
             */
            BOOST_RANDOM_DECL double entropy() const {
            }
            /** Returns a random value in the range [min, max]. */
            BOOST_RANDOM_DECL result_type operator()() {
                return nil::crypto3::accumulators::extract::stream<StreamCipher>(acc);
            }

            /** Fills a range with random values. */
            template<class Iter>
            void generate(Iter begin, Iter end) {
                nil::crypto3::detail::pack(nil::crypto3::accumulators::extract::stream<StreamCipher>(acc), begin, end);
            }

        protected:
            template<typename InputIterator>
            void update(InputIterator first, InputIterator last) {
                using namespace nil::crypto3;

                mac_key = encrypt<StreamCipher>({0}, mac::compute<mac_type>(first, last, mac_key), acc);
            }

            std::size_t cnt;
            key_type mac_key;
            nil::crypto3::accumulator_set<StreamCipher> acc;
        };
    }    // namespace random
}    // namespace boost

#endif /* BOOST_RANDOM_RANDOM_DEVICE_HPP */
