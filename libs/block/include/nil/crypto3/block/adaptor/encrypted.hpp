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

#ifndef CRYPTO3_ENCRYPTED_HPP
#define CRYPTO3_ENCRYPTED_HPP

#include <boost/range/adaptor/argument_fwd.hpp>
#include <boost/range/detail/default_constructible_unary_fn.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/range/concepts.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/utility/result_of.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            // A type generator to produce the transform_iterator type conditionally
            // including a wrapped predicate as appropriate.
            template<typename P, typename It>
            struct transform_iterator_gen {
                typedef boost::transform_iterator<typename boost::range_detail::default_constructible_unary_fn_gen<
                                                      P,
                                                      typename boost::transform_iterator<P, It>::reference>::type,
                                                  It>
                    type;
            };

            template<class F, class R>
            struct encoded_range
                : public boost::iterator_range<
                      typename transform_iterator_gen<F, typename boost::range_iterator<R>::type>::type> {
            private:
                typedef
                    typename transform_iterator_gen<F, typename boost::range_iterator<R>::type>::type transform_iter_t;

                typedef boost::iterator_range<transform_iter_t> base;

            public:
                typedef typename boost::range_detail::default_constructible_unary_fn_gen<
                    F,
                    typename boost::transform_iterator<F, typename boost::range_iterator<R>::type>::reference>::type
                    transform_fn_type;

                typedef R source_range_type;

                encoded_range(transform_fn_type f, R &r) :
                    base(transform_iter_t(boost::begin(r), f), transform_iter_t(boost::end(r), f)) {
                }
            };

            template<class T>
            struct encode_holder : boost::range_detail::holder<T> {
                encode_holder(T r) : boost::range_detail::holder<T>(r) {
                }
            };

            template<class SinglePassRange, class UnaryFunction>
            inline encoded_range<UnaryFunction, SinglePassRange> operator|(SinglePassRange &r,
                                                                           const encode_holder<UnaryFunction> &f) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                return encoded_range<UnaryFunction, SinglePassRange>(f.val, r);
            }

            template<class SinglePassRange, class UnaryFunction>
            inline encoded_range<UnaryFunction, const SinglePassRange>
                operator|(const SinglePassRange &r, const encode_holder<UnaryFunction> &f) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                return encoded_range<UnaryFunction, const SinglePassRange>(f.val, r);
            }

        }    // namespace detail

        using detail::encoded_range;

        namespace adaptors {
            namespace {
                const range_detail::forwarder<detail::encode_holder> encoded =
                    detail::forwarder<detail::encode_holder>();
            }

            template<class UnaryFunction, class SinglePassRange>
            inline encoded_range<UnaryFunction, SinglePassRange> transform(SinglePassRange &rng, UnaryFunction fn) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                return encoded_range<UnaryFunction, SinglePassRange>(fn, rng);
            }

            template<class UnaryFunction, class SinglePassRange>
            inline encoded_range<UnaryFunction, const SinglePassRange> transform(const SinglePassRange &rng,
                                                                                 UnaryFunction fn) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                return encoded_range<UnaryFunction, const SinglePassRange>(fn, rng);
            }
        }    // namespace adaptors
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ENCRYPTED_HPP
