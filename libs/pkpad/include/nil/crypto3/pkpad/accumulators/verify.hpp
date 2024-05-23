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

#ifndef CRYPTO3_ACCUMULATORS_PK_PAD_VERIFY_HPP
#define CRYPTO3_ACCUMULATORS_PK_PAD_VERIFY_HPP

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
        namespace pubkey {
            namespace padding {
                namespace accumulators {
                    namespace impl {
                        template<typename ProcessingPolicy, typename = void>
                        struct verify_impl;

                        template<typename ProcessingPolicy>
                        struct verify_impl<ProcessingPolicy> : boost::accumulators::accumulator_base {
                        protected:
                            typedef ProcessingPolicy processing_policy;
                            typedef typename processing_policy::msg_repr_type msg_repr_type;
                            typedef typename processing_policy::internal_accumulator_type internal_accumulator_type;

                        public:
                            typedef typename processing_policy::result_type result_type;

                            template<typename Args>
                            verify_impl(const Args &args) : msg_repr(args[boost::accumulators::sample]) {
                            }

                            template<typename Args>
                            inline void operator()(const Args &args) {
                                resolve_type(args[boost::accumulators::sample],
                                             args[::nil::crypto3::accumulators::iterator_last | nullptr]);
                            }

                            inline result_type result(boost::accumulators::dont_care) const {
                                return processing_policy::process(acc, msg_repr);
                            }

                        protected:
                            template<typename InputRange, typename InputIterator>
                            inline void resolve_type(const InputRange &range, InputIterator) {
                                processing_policy::update(acc, range);
                            }

                            template<typename InputIterator>
                            inline void resolve_type(InputIterator first, InputIterator last) {
                                processing_policy::update(acc, first, last);
                            }

                            msg_repr_type msg_repr;
                            internal_accumulator_type acc;
                        };
                    }    // namespace impl

                    namespace tag {
                        template<typename ProcessingPolicy>
                        struct verify : boost::accumulators::depends_on<> {
                            typedef ProcessingPolicy processing_policy;

                            /// INTERNAL ONLY
                            ///

                            typedef boost::mpl::always<accumulators::impl::verify_impl<processing_policy>> impl;
                        };
                    }    // namespace tag

                    namespace extract {
                        template<typename ProcessingPolicy, typename AccumulatorSet>
                        typename boost::mpl::apply<AccumulatorSet, tag::verify<ProcessingPolicy>>::type::result_type
                            verify(const AccumulatorSet &acc) {
                            return boost::accumulators::extract_result<tag::verify<ProcessingPolicy>>(acc);
                        }
                    }    // namespace extract
                }        // namespace accumulators
            }            // namespace padding
        }                // namespace pubkey
    }                    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_PK_PAD_VERIFY_HPP
