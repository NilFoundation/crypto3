//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_PUBKEY_PADDING_ENCODE_HPP
#define CRYPTO3_ACCUMULATORS_PUBKEY_PADDING_ENCODE_HPP

#include <iterator>
#include <type_traits>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/pkpad/accumulators/parameters/iterator_last.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename EncodingPolicy, typename = void>
                struct encode_impl;

                template<typename EncodingPolicy>
                struct encode_impl<EncodingPolicy> : boost::accumulators::accumulator_base {
                protected:
                    typedef EncodingPolicy encoding_policy_type;
                    typedef typename encoding_policy_type::msg_repr_type msg_repr_type;
                    typedef typename encoding_policy_type::accumulator_type accumulator_type;

                public:
                    typedef msg_repr_type result_type;

                    template<typename Args>
                    encode_impl(const Args &args) {
                    }

                    template<typename Args>
                    inline void operator()(const Args &args) {
                        resolve_type(args[boost::accumulators::sample], args[iterator_last | nullptr]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return encoding_policy_type::process(acc);
                    }

                protected:
                    template<typename InputRange, typename InputIterator>
                    inline void resolve_type(const InputRange &range, InputIterator) {
                        encoding_policy_type::update(acc, range);
                    }

                    template<typename InputIterator>
                    inline void resolve_type(InputIterator first, InputIterator last) {
                        encoding_policy_type::update(acc, first, last);
                    }

                    accumulator_type acc;
                };
            }    // namespace impl

            namespace tag {
                template<typename EncodingPolicy>
                struct encode : boost::accumulators::depends_on<> {
                    typedef EncodingPolicy encoding_policy_type;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::encode_impl<encoding_policy_type>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename EncodingPolicy, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::encode<EncodingPolicy>>::type::result_type
                    encode(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::encode<Mode>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PUBKEY_PADDING_ENCODE_HPP
