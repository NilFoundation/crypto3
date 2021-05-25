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

#ifndef BOOST_RANDOM_HASH_HPP
#define BOOST_RANDOM_HASH_HPP

#include <string>

#include <boost/config.hpp>
#include <boost/noncopyable.hpp>
#include <boost/random/detail/auto_link.hpp>
#include <boost/tti/has_type.hpp>
#include <boost/system/config.hpp>    // force autolink to find Boost.System

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/pack_numeric.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>

namespace nil {
    namespace crypto3 {
        namespace random {
            template<typename Hash, typename ResultType = multiprecision::cpp_int>
            struct hash : private boost::noncopyable {
                typedef Hash hash_type;
                typedef ResultType result_type;

                BOOST_STATIC_ASSERT(std::numeric_limits<result_type>::is_specialized ?
                                        std::numeric_limits<result_type>::digits <= hash_type::digest_bits :
                                        true);

                BOOST_STATIC_CONSTANT(std::size_t, reseed_interval = 256);

                BOOST_STATIC_CONSTANT(bool, has_fixed_range = false);

                /** Returns the smallest value that the \random_device can produce. */
                static BOOST_CONSTEXPR std::size_t min BOOST_PREVENT_MACRO_SUBSTITUTION() {
                    return 0;
                }
                /** Returns the largest value that the \random_device can produce. */
                static BOOST_CONSTEXPR std::size_t max BOOST_PREVENT_MACRO_SUBSTITUTION() {
                    return std::numeric_limits<result_type>::is_specialized ? std::numeric_limits<result_type>::max :
                                                                              ~0u;
                }

                /** Constructs a @c random_device, optionally using the default device. */
                BOOST_RANDOM_DECL hash() {
                }
                /**
                 * Constructs a @c random_device, optionally using the given token as an
                 * access specification (for example, a URL) to some implementation-defined
                 * service for monitoring a stochastic process.
                 */
                template<typename SeedSinglePassRange>
                BOOST_RANDOM_DECL explicit hash(const SeedSinglePassRange &token) {
                }

                BOOST_RANDOM_DECL ~hash() {
                }

                /** default seeds the underlying generator. */
                void seed(std::size_t s = 0) {
                    idx = s;
                }

                /** Seeds the underlying generator with first and last. */
                template<typename InputIterator>
                void seed(InputIterator &first, InputIterator last) {
                    while (first != last) {
                        idx ^= *first++;
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
                    result_type rval;

                    do {
                        uint64_t iter = 0;

                        std::array<std::size_t, 2> input = {idx, iter};
                        typename Hash::digest_type hash = crypto3::hash<Hash>(input);
                        crypto3::detail::pack(hash, rval);

                        iter++;
                    } while (rval == result_type());

                    return rval;
                }

                /** Fills a range with random values. */
                template<class Iter>
                void generate(Iter begin, Iter end) {
                    while (begin != end) {
                        *begin++ = this->operator()();
                    }
                }

            protected:
                std::size_t idx;
            };
        }    // namespace random
    }        // namespace crypto3
}    // namespace nil

#endif /* BOOST_RANDOM_RANDOM_DEVICE_HPP */
