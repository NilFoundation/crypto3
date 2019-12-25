//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_HASH_HPP
#define CRYPTO3_ACCUMULATORS_HASH_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <boost/container/static_vector.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

#include <nil/crypto3/hash/accumulators/bits_count.hpp>

#include <nil/crypto3/hash/accumulators/parameters/bits.hpp>
#include <nil/crypto3/hash/accumulators/parameters/salt.hpp>

#include <boost/accumulators/statistics/count.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Hash>
                struct hash_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef typename hash_type::construction::type construction_type;
                    typedef typename hash_type::construction::params_type params_type;

                    constexpr static const std::size_t word_bits = construction_type::word_bits;
                    typedef typename construction_type::word_type word_type;

                    constexpr static const std::size_t state_bits = construction_type::state_bits;
                    constexpr static const std::size_t state_words = construction_type::state_words;
                    typedef typename construction_type::state_type state_type;

                    constexpr static const std::size_t block_bits = construction_type::block_bits;
                    constexpr static const std::size_t block_words = construction_type::block_words;
                    typedef typename construction_type::block_type block_type;

                    constexpr static const std::size_t length_bits = params_type::length_bits;
                    // FIXME: do something more intelligent than capping at 64
                    constexpr static const std::size_t length_type_bits =
                        length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                    typedef typename boost::uint_t<length_type_bits>::least length_type;
                    constexpr static const std::size_t length_words = length_bits / word_bits;
                    BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);

                public:
                    typedef typename hash_type::digest_type result_type;

                    // The constructor takes an argument pack.
                    hash_impl(boost::accumulators::dont_care) : seen_bits(0), cache_words(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        seen_bits = extract::bits_count(args);
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::bits | std::size_t()]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        construction_type res = construction;
                        return res.digest(cache, seen_bits % block_bits);
                    }

                protected:
                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        process(value, bits);
                    }

                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        process(value, bits);
                    }

                    inline void cache_block(const block_type &value) {
                        length_type i = 0, cache_count = seen_bits % block_bits, j = cache_count / word_bits;

                        while (cache_count != block_words) {
                            cache[cache_words + j] = value[i];
                            ++cache_words;
                            ++i;
                        }
                        if (cache_count == block_words) {
                            cache_words = 0;
                            process(value, 0);
                        }
                    }

                    inline void process(const block_type &value, std::size_t bits) {
                        length_type cached_bits = (seen_bits - bits) % block_bits;

                        if (cached_bits != 0) {
                            std::move(value.begin(), value.begin() + (block_bits - cached_bits),
                                      cache.begin() + cached_bits);
                            cached_bits += block_bits - cached_bits;
                            if (cached_bits == block_bits) {
                                construction.process_block(cache);
                                std::move(value.begin() + (block_bits - cached_bits), value.end(), cache.begin());
                            }
                        } else {
                            if (bits == block_bits) {
                                construction.process_block(value);
                            } else {
                                std::move(value.begin(), value.end(), cache.begin());
                            }
                        }
                    }

                    inline void process(const word_type &value, std::size_t bits) {
                        length_type cached_bits = (seen_bits - bits) % block_bits;

                        if (cached_bits != 0) {
                            cache[cached_bits + 1] = value;
                            cached_bits += block_bits - cached_bits;
                            if (cached_bits == block_bits) {
                                construction.process_block(cache);
                            }
                        } else {
                            if (bits == block_bits) {
                                construction.process_block(value);
                            } else {
                                cache[0] = value;
                            }
                        }
                    }

                    length_type seen_bits, cache_words;
                    block_type cache;
                    construction_type construction;
                };
            }    // namespace impl

            namespace tag {
                template<typename Hash>
                struct hash : boost::accumulators::depends_on<bits_count> {
                    typedef Hash hash_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::hash_impl<Hash>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Hash, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::hash<Hash>>::type::result_type
                    hash(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::hash<Hash>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP