//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_RANDOM_CHACHA_HPP
#define CRYPTO3_RANDOM_CHACHA_HPP

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

namespace nil {
    namespace crypto3 {
        namespace random {

            /*!
             * @brief
             * @tparam StreamCipher
             * @tparam MessageAuthenticationCode
             *
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
            template<typename StreamCipher = stream::chacha<64, 128, 20>,
                     typename MessageAuthenticationCode = mac::hmac<hashes::sha2<256>>>
            struct chacha : private boost::noncopyable {
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
                    return accumulators::extract::stream<StreamCipher>(acc);
                }

                /** Fills a range with random values. */
                template<class Iter>
                void generate(Iter begin, Iter end) {
                    detail::pack(accumulators::extract::stream<StreamCipher>(acc), begin, end);
                }

            protected:
                template<typename InputIterator>
                void update(InputIterator first, InputIterator last) {
                    mac_key = encrypt<StreamCipher>({0}, compute<mac_type>(first, last, mac_key), acc);
                }

                std::size_t cnt;
                key_type mac_key;
                stream::accumulator_set<StreamCipher> acc;
            };
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif /* BOOST_RANDOM_RANDOM_DEVICE_HPP */
