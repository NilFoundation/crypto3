//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_BLOCK_HPP
#define CRYPTO3_ACCUMULATORS_BLOCK_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/block/detail/make_array.hpp>
#include <nil/crypto3/block/detail/digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct block_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename mode_type::finalizer_type finalizer_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t state_bits = mode_type::state_bits;
                    constexpr static const std::size_t state_words = mode_type::state_words;
                    typedef typename mode_type::state_type state_type;

                    constexpr static const std::size_t block_bits = mode_type::block_bits;
                    constexpr static const std::size_t block_words = mode_type::block_words;
                    typedef typename mode_type::block_type block_type;

                    typedef boost::container::static_vector<word_type, block_words> cache_type;

                public:
                    typedef block::digest<block_bits> result_type;

                    template<typename Args>
                    // The constructor takes an argument pack.
                    block_impl(const Args &args) : seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        return process(args[boost::accumulators::sample]);
                    }

                    template<typename ArgumentPack>
                    inline result_type result(const ArgumentPack &args) const {
                        result_type res = digest;

                        if (!cache.empty()) {
                            block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            block_type ob = mode_type::process_block(ib);
                            std::move(ob.begin(), ob.end(), std::inserter(res, res.end()));
                        }

                        if (seen % block_bits) {
                            finalizer_type(block_bits - seen % block_bits)(res);
                        } else {
                            finalizer_type(0)(res);
                        }

                        return res;
                    }

                protected:
                    inline void resolve_type(const word_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, word_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    inline void resolve_type(const block_type &value, std::size_t bits) {
                        if (bits == std::size_t()) {
                            process(value, block_bits);
                        } else {
                            process(value, bits);
                        }
                    }

                    inline void process(const word_type &value, std::size_t bits) {
                        if (cache.size() == cache.max_size()) {
                            block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            block_type ob = mode_type::process_block(ib);
                            std::move(ob.begin(), ob.end(), std::inserter(digest, digest.end()));

                            cache.clear();
                        }

                        cache.push_back(value);
                        seen += bits;
                    }

                    inline void process(const block_type &block, std::size_t bits) {
                        block_type ob;
                        if (cache.empty()) {
                            ob = mode_type::process_block(block);
                        } else {
                            block_type b = block::make_array<block_words>(cache.begin(), cache.end());
                            typename block_type::const_iterator itr = block.begin() + (cache.max_size() - cache.size());

                            std::copy(block.begin(), itr, b.end());

                            ob = mode_type::process_block(block);

                            cache.clear();
                            cache.insert(cache.end(), itr, block.end());
                        }

                        std::move(ob.begin(), ob.end(), std::inserter(digest, digest.end()));
                        seen += bits;
                    }

                    std::size_t seen;
                    cache_type cache;
                    result_type digest;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct block : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::block_impl<Mode>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::block<Mode>>::type::result_type
                    block(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::block<Mode>>(acc);
                }

                template<typename Cipher, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet,
                                           tag::block<typename Cipher::stream_encrypter_mode>>::type::result_type
                    encrypt(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::block<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP
