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

#ifndef CRYPTO3_ACCUMULATORS_BLOCK_HPP
#define CRYPTO3_ACCUMULATORS_BLOCK_HPP

#include <boost/container/static_vector.hpp>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/block/accumulators/block.hpp>

#include <nil/crypto3/detail/make_array.hpp>
#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            template<typename BlockCipher>
            struct cbc_mac;
        }
        namespace accumulators {
            namespace impl {
                template<typename MessageAuthenticationCode>
                struct mac_impl;

                template<typename BlockCipher>
                struct mac_impl<mac::cbc_mac<BlockCipher>> : boost::accumulators::accumulator_base {
                protected:
                    typedef BlockCipher cipher_type;
                    typedef mac::cbc_mac<cipher_type> mac_type;

                    constexpr static const std::size_t word_bits = mac_type::word_bits;
                    typedef typename mac_type::word_type word_type;

                    constexpr static const std::size_t state_bits = mac_type::state_bits;
                    constexpr static const std::size_t state_words = mac_type::state_words;
                    typedef typename mac_type::state_type state_type;

                    constexpr static const std::size_t block_bits = mac_type::block_bits;
                    constexpr static const std::size_t block_words = mac_type::block_words;
                    typedef typename mac_type::block_type block_type;

                    typedef boost::container::static_vector<word_type, block_words> cache_type;

                public:
                    typedef block::digest<block_bits> result_type;

                    template<typename Args>
                    mac_impl(const Args &args) : cipher(args[accumulators::cipher]), seen(0) {
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        return process(args[boost::accumulators::sample]);
                    }

                    template<typename ArgumentPack>
                    inline result_type result(const ArgumentPack &args) const {
                        result_type res = digest;

                        return res;
                    }

                protected:
                    inline void process(const block_type &block, std::size_t bits) {
                    }

                    mac_type mac;

                    std::size_t seen;
                    cache_type cache;
                    result_type digest;
                };
            }    // namespace impl

            namespace tag {
                template<typename MessageAuthenticationCode>
                struct mac : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::mac_impl<MessageAuthenticationCode>> impl;
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
