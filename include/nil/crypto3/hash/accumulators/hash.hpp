//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ACCUMULATORS_HASH_HPP
#define CRYPTO3_ACCUMULATORS_HASH_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/hash/detail/make_array.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Hash>
                struct hash_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef typename hash_type::block_hash_type block_hash_type;

                    constexpr static const std::size_t word_bits = block_hash_type::word_bits;
                    typedef typename block_hash_type::word_type word_type;

                    constexpr static const std::size_t state_bits = block_hash_type::state_bits;
                    constexpr static const std::size_t state_words = block_hash_type::state_words;
                    typedef typename block_hash_type::state_type state_type;

                    constexpr static const std::size_t block_bits = block_hash_type::block_bits;
                    constexpr static const std::size_t block_words = block_hash_type::block_words;
                    typedef typename block_hash_type::block_type block_type;

                    typedef boost::container::static_vector<word_type, block_words> cache_type;

                public:
                    typedef typename Hash::digest_type result_type;

                    template<typename Args>
                    // The constructor takes an argument pack.
                    hash_impl(const Args &args) : seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        return process(args[boost::accumulators::sample]);
                    }

                    template<typename ArgumentPack>
                    inline result_type result(const ArgumentPack &args) const {
                        block_hash_type res = construction;

                        if (!cache.empty()) {
                            block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            res.update(ib);
                        }

                        return res.end_message();
                    }

                protected:

                    inline void process(const word_type &value) {
                        if (cache.size() == cache.max_size()) {
                            block_type ib = {0};
                            std::move(cache.begin(), cache.end(), ib.begin());
                            construction.update(ib);

                            cache.clear();
                        }

                        cache.push_back(value);
                        seen += word_bits;
                    }

                    inline void process(const block_type &block) {
                        if (cache.empty()) {
                            construction.update(block);
                        } else {
                            block_type b = hash::make_array<block_words>(cache.begin(), cache.end());
                            typename block_type::const_iterator itr = block.begin() + (cache.max_size() - cache.size());

                            std::move(block.begin(), itr, b.end());

                            construction.update(b);

                            cache.clear();
                            cache.insert(cache.end(), itr, block.end());
                        }

                        seen += block_bits;
                    }

                    std::size_t seen;
                    cache_type cache;
                    block_hash_type construction;
                };
            }

            namespace tag {
                template<typename Hash>
                struct hash : boost::accumulators::depends_on<> {
                    typedef Hash hash_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::hash_impl<Hash>> impl;
                };
            }

            namespace extract {
                template<typename Hash, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::hash<Hash> >::type::result_type hash(
                        const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::hash<Hash> >(acc);
                }
            }
        }
    }
}

#endif //CRYPTO3_ACCUMULATORS_BLOCK_HPP
