//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>
#include <nil/crypto3/detail/inject.hpp>

#include <nil/crypto3/block/accumulators/bits_count.hpp>

#include <nil/crypto3/block/accumulators/parameters/cipher.hpp>
#include <nil/crypto3/block/accumulators/parameters/bits.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>
#include <nil/crypto3/block/detail/cipher_modes.hpp>

#include <nil/crypto3/block/cipher.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct block_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename Mode::cipher_type cipher_type;
                    typedef typename Mode::padding_type padding_type;

                    typedef typename mode_type::endian_type endian_type;

                    constexpr static const std::size_t word_bits = mode_type::word_bits;
                    typedef typename mode_type::word_type word_type;

                    constexpr static const std::size_t block_bits = mode_type::block_bits;
                    constexpr static const std::size_t block_words = mode_type::block_words;
                    typedef typename mode_type::block_type block_type;

                    typedef ::nil::crypto3::detail::injector<endian_type, word_bits, block_words, block_bits>
                        injector_type;

                    typedef ::nil::crypto3::detail::packer<endian_type, endian_type, word_bits, octet_bits> 
                        packer_type;

                public:
                    typedef digest<block_bits> result_type;

                    template<typename Args>
                    block_impl(const Args &args) :
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

                        block_type processed_block = mode.end_message(cache, total_seen);

                        packer_type::pack(processed_block.begin(), processed_block.end(), res.end());

                        /*std::move(processed_block.begin(), processed_block.end(), std::inserter(new_dgst_part, new_dgst_part.end()));

                        res.insert(res.end(), processed_block.begin(), processed_block.end());

                        std::reverse(res.begin(), res.end());*/

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
                        std::cout << "In process block" << std::endl;

                        using namespace ::nil::crypto3::detail;

                        block_type processed_block;
                        if (dgst.empty()) {
                            processed_block = mode.begin_message(cache, total_seen);
                        } else {
                            processed_block = mode.process_block(cache, total_seen);
                        }

                        packer_type::pack(processed_block.begin(), processed_block.end(), dgst.end());

                        /*std::move(processed_block.begin(), processed_block.end(), std::inserter(new_dgst_part, new_dgst_part.end()));

                        res.insert(res.end(), processed_block.begin(), processed_block.end());*/
                        
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
                                // If there are enough bits in the incoming value to fill the block
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
                                // The incoming value is a full block
                                filled = true;

                                std::move(value.begin(), value.end(), cache.begin());

                            } else {
                                // The incoming value is not a full block
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
                                // If there are enough bits in the incoming value to fill the block

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
                struct block : boost::accumulators::depends_on<bits_count> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::block_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::block<Mode>>::type::result_type
                    block(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::block<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP
