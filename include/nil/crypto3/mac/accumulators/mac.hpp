//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ACCUMULATORS_MAC_HPP
#define CRYPTO3_ACCUMULATORS_MAC_HPP

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/mac/accumulators/parameters/iterator_last.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            namespace impl {
                template<typename ProcessingPolicy>
                struct mac_impl : boost::accumulators::accumulator_base {
                protected:
                    typedef ProcessingPolicy processing_policy;
                    typedef typename processing_policy::mac_type mac_type;
                    typedef typename processing_policy::key_type key_type;
                    typedef typename processing_policy::internal_accumulator_type internal_accumulator_type;

                public:
                    typedef typename processing_policy::result_type result_type;

                    template<typename Args>
                    mac_impl(const Args &args) : key(args[boost::accumulators::sample]) {
                        processing_policy::init_accumulator(key, acc);
                    }

                    template<typename ArgumentPack>
                    inline void operator()(const ArgumentPack &args) {
                        resolve_type(args[boost::accumulators::sample],
                                     args[::nil::crypto3::accumulators::iterator_last | nullptr]);
                    }

                    inline result_type result(boost::accumulators::dont_care) const {
                        return processing_policy::process(key, acc);
                    }

                protected:
                    template<typename InputRange, typename InputIterator>
                    inline void resolve_type(const InputRange &range, InputIterator) {
                        processing_policy::update(key, acc, range);
                    }

                    template<typename InputIterator>
                    inline void resolve_type(InputIterator first, InputIterator second) {
                        processing_policy::update(key, acc, first, second);
                    }

                    key_type key;
                    mutable internal_accumulator_type acc;
                };
            }    // namespace impl

            namespace tag {
                template<typename ProcessingPolicy>
                struct mac : boost::accumulators::depends_on<> {
                    typedef ProcessingPolicy processing_policy;

                    /// INTERNAL ONLY
                    ///

                    typedef boost::mpl::always<accumulators::impl::mac_impl<processing_policy>> impl;
                };
            }    // namespace tag

            namespace extract {
                template<typename ProcessingPolicy, typename AccumulatorSet>
                typename boost::mpl::apply<AccumulatorSet, tag::mac<ProcessingPolicy>>::type::result_type
                    mac(const AccumulatorSet &acc) {
                    return boost::accumulators::extract_result<tag::mac<ProcessingPolicy>>(acc);
                }
            }    // namespace extract
        }        // namespace accumulators
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_MAC_HPP
