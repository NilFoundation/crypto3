//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_DECRYPTED_HPP
#define CRYPTO3_DECRYPTED_HPP

#include <boost/range/adaptor/argument_fwd.hpp>
#include <boost/range/detail/default_constructible_unary_fn.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/range/concepts.hpp>
#include <boost/iterator/transform_iterator.hpp>
#include <boost/utility/result_of.hpp>

namespace nil {
    namespace range_detail {
        // A type generator to produce the transform_iterator type conditionally
        // including a wrapped predicate as appropriate.
        template<typename P, typename It>
        struct transform_iterator_gen {
            typedef transform_iterator<
                typename default_constructible_unary_fn_gen<P, typename transform_iterator<P, It>::reference>::type,
                It>
                type;
        };

        template<class F, class R>
        struct decoded_range
            : public boost::iterator_range<typename transform_iterator_gen<F, typename range_iterator<R>::type>::type> {
        private:
            typedef typename transform_iterator_gen<F, typename range_iterator<R>::type>::type transform_iter_t;

            typedef boost::iterator_range<transform_iter_t> base;

        public:
            typedef typename default_constructible_unary_fn_gen<
                F,
                typename transform_iterator<F, typename range_iterator<R>::type>::reference>::type transform_fn_type;

            typedef R source_range_type;

            decoded_range(transform_fn_type f, R &r) :
                base(transform_iter_t(boost::begin(r), f), transform_iter_t(boost::end(r), f)) {
            }
        };

        template<class T>
        struct transform_holder : holder<T> {
            transform_holder(T r) : holder<T>(r) {
            }
        };

        template<class SinglePassRange, class UnaryFunction>
        inline decoded_range<UnaryFunction, SinglePassRange> operator|(SinglePassRange &r,
                                                                       const transform_holder<UnaryFunction> &f) {
            BOOST_RANGE_CONCEPT_ASSERT((SinglePassRangeConcept<SinglePassRange>));

            return decoded_range<UnaryFunction, SinglePassRange>(f.val, r);
        }

        template<class SinglePassRange, class UnaryFunction>
        inline decoded_range<UnaryFunction, const SinglePassRange> operator|(const SinglePassRange &r,
                                                                             const transform_holder<UnaryFunction> &f) {
            BOOST_RANGE_CONCEPT_ASSERT((SinglePassRangeConcept<const SinglePassRange>));

            return decoded_range<UnaryFunction, const SinglePassRange>(f.val, r);
        }

    }    // namespace range_detail

    using range_detail::decoded_range;

    namespace adaptors {
        namespace {
            const range_detail::forwarder<range_detail::transform_holder> decoded =
                range_detail::forwarder<range_detail::transform_holder>();
        }

        template<class UnaryFunction, class SinglePassRange>
        inline decoded_range<UnaryFunction, SinglePassRange> transform(SinglePassRange &rng, UnaryFunction fn) {
            BOOST_RANGE_CONCEPT_ASSERT((SinglePassRangeConcept<SinglePassRange>));

            return decoded_range<UnaryFunction, SinglePassRange>(fn, rng);
        }

        template<class UnaryFunction, class SinglePassRange>
        inline decoded_range<UnaryFunction, const SinglePassRange> transform(const SinglePassRange &rng,
                                                                             UnaryFunction fn) {
            BOOST_RANGE_CONCEPT_ASSERT((SinglePassRangeConcept<const SinglePassRange>));

            return decoded_range<UnaryFunction, const SinglePassRange>(fn, rng);
        }
    }    // namespace adaptors

}    // namespace nil

#endif    // CRYPTO3_DECRYPTED_HPP
