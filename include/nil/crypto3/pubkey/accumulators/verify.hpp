//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_PUBLIC_KEY_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_PUBLIC_KEY_HPP

#include <unordered_map>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pubkey/public_key.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/key.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename Mode>
                struct verify_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef Mode mode_type;
                    typedef typename mode_type::scheme_type scheme_type;
                    typedef typename mode_type::padding_type padding_type;
                    typedef typename mode_type::key_type key_type;

                    constexpr static const auto block_bits = mode_type::input_block_bits;
                    typedef typename mode_type::input_block_type block_type;

                    constexpr static const auto value_bits = mode_type::input_value_bits;
                    typedef typename mode_type::input_value_type value_type;

                    typedef typename key_type::aggregate_verification_type cache_type;

                public:
                    typedef typename mode_type::result_type result_type;

                    template<typename Args>
                    verify_impl(const Args &args) : init_key(args[boost::accumulators::sample])//, cache(cache_type{{init_key.pubkey_id, std::make_pair(init_key, block_type())}})
                    {
                        init_key.append_aggregated_msg(cache);
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::key | init_key]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return mode_type::process(init_key, cache);
                    }

                protected:
                    inline void resolve_type(const block_type &block, const key_type &key) {
                        key.append_aggregated_msg(cache, block);
                    }

                    inline void resolve_type(const value_type &value, const key_type &key) {
                        key.append_aggregated_msg(cache, value);
                    }

                    key_type init_key;
                    cache_type cache;
                };
            }    // namespace impl

            namespace tag {
                template<typename Mode>
                struct verify : boost::accumulators::depends_on<> {
                    typedef Mode mode_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::verify_impl<mode_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename Mode, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::verify<Mode>>::type::result_type
                    scheme(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::verify<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_PUBLIC_KEY_HPP
