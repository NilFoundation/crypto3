//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_SNARK_HPP
#define CRYPTO3_ACCUMULATORS_SNARK_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/snark/accumulators/bits_count.hpp>

#include <nil/crypto3/snark/accumulators/parameters/cipher.hpp>
#include <nil/crypto3/snark/accumulators/parameters/bits.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>
#include <nil/crypto3/snark/detail/cipher_modes.hpp>

#include <nil/crypto3/snark/cipher.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct snark_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::cipher_type cipher_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t snark_bits = mode_type::snark_bits;
                    constexpr static const std::size_t snark_words = mode_type::snark_words;
                    typedef typename mode_type::snark_type snark_type;

                    constexpr static const std::size_t value_bits = sizeof(typename snark_type::value_type) * CHAR_BIT;
                    constexpr static const std::size_t snark_values = snark_bits / value_bits;

                    typedef ::nil::crypto3::detail::injector<endian_type, value_bits, snark_values, snark_bits>
                        injector_type;

                public:
                    typedef digest<snark_bits> result_type;

                    template<typename Args>
                    snark_impl(const Args &args) :
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

                        snark_type processed_snark = mode.end_message(cache, total_seen);

                        res = ::nil::crypto3::resize<snark_bits>(res, res.size() + snark_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_snark.begin(), processed_snark.end(), res.end() - snark_values);

                        return res;
                    }

                protected:
                    inline void resolve_type(const snark_type &value, std::size_t bits) {
                        process(value, bits == 0 ? snark_bits : bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits == 0 ? word_bits : bits);
                    }

                    inline void process_snark() {
                        using namespace ::nil::crypto3::detail;

                        snark_type processed_snark;
                        if (dgst.empty()) {
                            processed_snark = mode.begin_message(cache, total_seen);
                        } else {
                            processed_snark = mode.process_snark(cache, total_seen);
                        }

                        dgst = ::nil::crypto3::resize<snark_bits>(dgst, dgst.size() + snark_values);

                        pack<endian_type, endian_type, value_bits, octet_bits>(
                            processed_snark.begin(), processed_snark.end(), dgst.end() - snark_values);

                        filled = false;
                    }

                    inline void process(const snark_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_snark();
                        }

                        std::size_t cached_bits = total_seen % snark_bits;

                        if (cached_bits != 0) {
                            // If there are already any bits in the cache

                            std::size_t needed_to_fill_bits = snark_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == snark_bits) {
                                // If there are enough bits in the incoming value to fill the snark
                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_snark();

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
                            if (value_seen == snark_bits) {
                                // The incoming value is a full snark
                                filled = true;

                                std::move(value.begin(), value.end(), cache.begin());

                            } else {
                                // The incoming value is not a full snark
                                std::move(value.begin(),
                                          value.begin() + value_seen / word_bits + (value_seen % word_bits ? 1 : 0),
                                          cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t value_seen) {
                        using namespace ::nil::crypto3::detail;

                        if (filled) {
                            process_snark();
                        }

                        std::size_t cached_bits = total_seen % snark_bits;

                        if (cached_bits % word_bits != 0) {
                            std::size_t needed_to_fill_bits = snark_bits - cached_bits;
                            std::size_t new_bits_to_append =
                                (needed_to_fill_bits > value_seen) ? value_seen : needed_to_fill_bits;

                            injector_type::inject(value, new_bits_to_append, cache, cached_bits);
                            total_seen += new_bits_to_append;

                            if (cached_bits == snark_bits) {
                                // If there are enough bits in the incoming value to fill the snark

                                filled = true;

                                if (value_seen > new_bits_to_append) {

                                    process_snark();

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
                    snark_type cache;
                    result_type dgst;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct snark : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::snark_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::snark<Mode>>::type::result_type
                    snark(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::snark<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_SNARK_HPP
