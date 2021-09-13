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

#ifndef CRYPTO3_ACCUMULATORS_HASH_TO_CURVE_HPP
#define CRYPTO3_ACCUMULATORS_HASH_TO_CURVE_HPP

#include <iterator>
#include <type_traits>

#include <boost/parameter/value_type.hpp>

#include <boost/accumulators/framework/accumulator_base.hpp>
#include <boost/accumulators/framework/extractor.hpp>
#include <boost/accumulators/framework/depends_on.hpp>
#include <boost/accumulators/framework/parameters/sample.hpp>

#include <nil/crypto3/hash/accumulators/parameters/iterator_last.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace accumulators {
                namespace impl {
                    template<typename HashingPolicy, typename = void>
                    struct to_curve_impl;

                    // TODO: maybe add dependant hash accumulator instead manually work with it inside
                    template<typename HashingPolicy>
                    struct to_curve_impl<HashingPolicy> : boost::accumulators::accumulator_base {
                    protected:
                        typedef HashingPolicy hashing_policy;
                        typedef typename hashing_policy::internal_accumulator_type internal_accumulator_type;

                    public:
                        typedef typename hashing_policy::result_type result_type;

                        template<typename Args>
                        to_curve_impl(const Args &args) {
                            hashing_policy::init_accumulator(acc);
                        }

                        template<typename Args>
                        inline void operator()(const Args &args) {
                            resolve_type(args[boost::accumulators::sample],
                                         args[::nil::crypto3::accumulators::iterator_last | nullptr]);
                        }

                        inline result_type result(boost::accumulators::dont_care) const {
                            return hashing_policy::process(acc);
                        }

                    protected:
                        template<typename InputRange, typename InputIterator>
                        inline void resolve_type(const InputRange &range, InputIterator) {
                            hashing_policy::update(acc, range);
                        }

                        template<typename InputIterator>
                        inline void resolve_type(InputIterator first, InputIterator last) {
                            hashing_policy::update(acc, first, last);
                        }

                        mutable internal_accumulator_type acc;
                    };
                }    // namespace impl

                namespace tag {
                    template<typename HashingPolicy>
                    struct to_curve : boost::accumulators::depends_on<> {
                        typedef HashingPolicy hashing_policy;

                        /// INTERNAL ONLY
                        ///

                        typedef boost::mpl::always<accumulators::impl::to_curve_impl<hashing_policy>> impl;
                    };
                }    // namespace tag

                namespace extract {
                    template<typename HashingPolicy, typename AccumulatorSet>
                    typename boost::mpl::apply<AccumulatorSet, tag::to_curve<HashingPolicy>>::type::result_type
                        to_curve(const AccumulatorSet &acc) {
                        return boost::accumulators::extract_result<tag::to_curve<HashingPolicy>>(acc);
                    }
                }    // namespace extract
            }        // namespace accumulators
        }            // namespace hashes
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ACCUMULATORS_HASH_TO_CURVE_HPP
