//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/pubkey/accumulators/bits_count.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/scheme.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/bits.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>
#include <nil/crypto3/pubkey/detail/scheme_modes.hpp>

#include <nil/crypto3/pubkey/scheme.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct pubkey_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::cipher_type cipher_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t pubkey_bits = mode_type::pubkey_bits;
                    constexpr static const std::size_t pubkey_words = mode_type::pubkey_words;
                    typedef typename mode_type::pubkey_type pubkey_type;

                    constexpr static const std::size_t value_bits = sizeof(typename pubkey_type::value_type) * CHAR_BIT;
                    constexpr static const std::size_t pubkey_values = pubkey_bits / value_bits;

                    typedef ::nil::crypto3::detail::injector<endian_type, value_bits, pubkey_values, pubkey_bits>
                        injector_type;

                public:
                    typedef digest<pubkey_bits> result_type;

                    template<typename Args>
                    pubkey_impl(const Args &args) :
                        total_seen(0), filled(false), mode(args[boost::accumulators::sample]) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        using namespace ::nil::crypto3::detail;

                        result_type res = dgst;

                        pubkey_type processed_pubkey = mode.end_message(cache, total_seen);

                        res = ::nil::crypto3::resize<pubkey_bits>(res, res.size() + pubkey_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_pubkey.begin(), processed_pubkey.end(), res.end() - pubkey_values);

                        return res;
                    }

                protected:
                    inline void resolve_type(const pubkey_type &value, std::size_t bits) {
                        process(value, bits == 0 ? pubkey_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process_pubkey() {
                        using namespace ::nil::crypto3::detail;

                        pubkey_type processed_pubkey;
                        if (dgst.empty()) {
                            processed_pubkey = mode.begin_message(cache, total_seen);
                        } else {
                            processed_pubkey = mode.process_pubkey(cache, total_seen);
                        }

                        dgst = ::nil::crypto3::resize<pubkey_bits>(dgst, dgst.size() + pubkey_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_pubkey.begin(), processed_pubkey.end(), dgst.end() - pubkey_values);

                        filled = false;
                    }

                    inline void process(const pubkey_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_pubkey();
                        }

                        std::size_t cached_bits = total_seen % pubkey_bits;

                        if (cached_bits != 0) {
                            // If there are already any bits in the cache

                            std::size_t needed_to_fill_bits = pubkey_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == pubkey_bits) {
                                // If there are enough bits in the incoming value to fill the pubkey
                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_pubkey();

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
                            if (value_seen == pubkey_bits) {
                                // The incoming value is a full pubkey
                                filled = true;

                                std::move(value.begin(), value.end(), cache.begin());

                            } else {
                                // The incoming value is not a full pubkey
                                std::move(value.begin(),
                                          value.begin() + value_seen / word_bits + (value_seen % word_bits ? 1 : 0),
                                          cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_pubkey();
                        }

                        std::size_t cached_bits = total_seen % pubkey_bits;

                        if (cached_bits % word_bits != 0) {
                            std::size_t needed_to_fill_bits = pubkey_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == pubkey_bits) {
                                // If there are enough bits in the incoming value to fill the pubkey

                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_pubkey();

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
                    pubkey_type cache;
                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct pubkey : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::pubkey_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::pubkey<Mode>>::type::result_type
                    pubkey(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::pubkey<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_HPP
