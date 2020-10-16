//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_BLOCK_HPP
#define CRYPTO3_ACCUMULATORS_BLOCK_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/mac/accumulators/parameters/mac.hpp>
#include <nil/crypto3/mac/accumulators/parameters/bits.hpp>

#include <nil/crypto3/hash/accumulators/parameters/hash.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/digest.hpp>

#include <nil/crypto3/block/cipher.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename Hash>
            struct hmac;
        }
        namespace accumulators {
            namespace impl {
                template<typename MessageAuthenticationCode>
                struct mac_impl;

                template<typename Hash>
                struct mac_impl<nil::crypto3::mac::hmac<Hash>> : boost::accumulators::accumulator_base {
                protected:
                    typedef Hash hash_type;
                    typedef nil::crypto3::mac::hmac<hash_type> mac_type;

                    typedef typename hash_type::construction::type construction_type;
                    typedef typename hash_type::construction::params_type params_type;

                    typedef typename params_type::digest_endian endian_type;

                    constexpr static const std::size_t word_bits = construction_type::word_bits;
                    typedef typename construction_type::word_type word_type;

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

                    typedef ::nil::crypto3::detail::injector<endian_type, word_bits, block_words, block_bits>
                        injector_type;

                public:
                    typedef typename hash_type::digest_type result_type;

                    mac_impl(boost::accumulators::dont_care) : total_seen(0), filled(false) {
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
                            block_type ob = cipher.end_message(ib);
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
                            block_type ob = digest.empty() ? cipher.begin_message(ib) : cipher.process_block(ib);
                            std::move(ob.begin(), ob.end(), std::inserter(digest, digest.end()));

                            cache.clear();
                        }

                        cache.push_back(value);
                        seen += bits;
                    }

                    inline void process(const block_type &block, std::size_t bits) {
                        block_type ob;
                        if (cache.empty()) {
                            ob = digest.empty() ? cipher.begin_message(block) : cipher.process_block(block);
                        } else {
                            block_type b = block::make_array<block_words>(cache.begin(), cache.end());
                            typename block_type::const_iterator itr = block.begin() + (cache.max_size() - cache.size());

                            std::copy(block.begin(), itr, b.end());

                            ob = digest.empty() ? cipher.begin_message(b) : cipher.process_block(b);

                            cache.clear();
                            cache.insert(cache.end(), itr, block.end());
                        }

                        std::move(ob.begin(), ob.end(), std::inserter(digest, digest.end()));
                        seen += bits;
                    }

                    block::cipher<cipher_type, mode_type, padding_type> cipher;

                    std::size_t seen;
                    block_type cache;
                    result_type digest;
                };
            }    // namespace impl

            namespace tag {
                template<typename MessageAuthenticationCode>
                struct mac : boost::accumulators::depends_on<hash> {
                    typedef MessageAuthenticationCode mac_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::mac_impl<mac_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename MessageAuthenticationCode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::mac<MessageAuthenticationCode>>::type::result_type
                    mac(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::mac<MessageAuthenticationCode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_BLOCK_HPP
