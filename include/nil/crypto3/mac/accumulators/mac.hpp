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

#ifndef CRYPTO3_ACCUMULATORS_MAC_HPP
#define CRYPTO3_ACCUMULATORS_MAC_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/mac/accumulators/bits_count.hpp>

#include <nil/crypto3/mac/accumulators/parameters/mac.hpp>
#include <nil/crypto3/mac/accumulators/parameters/bits.hpp>

//#include <nil/crypto3/mac/detail/mac_modes.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct mac_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::mac_type mac_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t block_bits = mode_type::block_bits;
                    constexpr static const std::size_t block_words = mode_type::mac_words;
                    typedef typename mode_type::block_type block_type;

                    constexpr static const std::size_t value_bits = sizeof(typename mac_type::value_type) * CHAR_BIT;
                    constexpr static const std::size_t block_values = block_bits / value_bits;

                    typedef ::nil::crypto3::detail::injector<endian_type, value_bits, block_values, block_bits>
                        injector_type;

                public:
                    typedef digest<block_bits> result_type;

                    template<typename Args>
                    mac_impl(const Args &args) : total_seen(0), filled(false), mode(args[boost::accumulators::sample]) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        using namespace ::nil::crypto3::detail;

                        result_type res = dgst;

                        mac_type processed_mac = mode.end_message(cache, total_seen);

                        res = ::nil::crypto3::resize<block_bits>(res, res.size() + block_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_mac.begin(), processed_mac.end(), res.end() - block_values);

                        return res;
                    }

                protected:
                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        process(value, bits == 0 ? block_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process_block() {
                        using namespace ::nil::crypto3::detail;

                        block_type processed_block;
                        if (dgst.empty()) {
                            processed_block = mode.begin_message(cache, total_seen);
                        } else {
                            processed_block = mode.process_block(cache, total_seen);
                        }

                        dgst = ::nil::crypto3::resize<block_bits>(dgst, dgst.size() + block_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_block.begin(), processed_block.end(), dgst.end() - block_values);

                        filled = false;
                    }

                    inline void process(const block_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_block();
                        }

                        std::size_t cached_bits = total_seen % block_bits;

                        if (cached_bits != 0) {
                            // If there are already any bits in the cache

                            std::size_t needed_to_fill_bits = block_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == block_bits) {
                                // If there are enough bits in the incoming value to fill the mac
                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_block();

                                    // If there are some remaining bits in the incoming value - put them into the cache,
                                    // which is now empty

                                    cached_bits = 0;

                                    injector_type::inject(value, value_seen - new_bits_to_append, cache, cached_bits,
                                                          new_bits_to_append);

                                    total_seen += value_seen - new_bits_to_append;
                                }
                            }

                        } else {

                            total_seen += value_seen;

                            // If there are no bits in the cache
                            if (value_seen == block_bits) {
                                // The incoming value is a full mac
                                filled = true;

                                std::move(value.begin(), value.end(), cache.begin());

                            } else {
                                // The incoming value is not a full mac
                                std::move(value.begin(),
                                          value.begin() + value_seen / word_bits + (value_seen % word_bits ? 1 : 0),
                                          cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_block();
                        }

                        std::size_t cached_bits = total_seen % block_bits;

                        if (cached_bits % word_bits != 0) {
                            std::size_t needed_to_fill_bits = block_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == block_bits) {
                                // If there are enough bits in the incoming value to fill the mac

                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_block();

                                    // If there are some remaining bits in the incoming value - put them into the cache,
                                    // which is now empty
                                    cached_bits = 0;

                                    injector_type::inject(value, value_seen - new_bits_to_append, cache, cached_bits,
                                                          new_bits_to_append);

                                    total_seen += value_seen - new_bits_to_append;
                                }
                            }

                        } else {
                            cache[cached_bits / word_bits] = value;

                            total_seen += value_seen;
                        }
                    }

                    mode_type mode;

                    bool filled;
                    std::size_t total_seen;
                    block_type cache;
                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct mac : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::mac_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::mac<Mode>>::type::result_type
                    mac(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::mac<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_MAC_HPP
