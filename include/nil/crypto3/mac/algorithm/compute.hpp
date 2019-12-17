//---------------------------------------------------------------------------//
// Copyright (c) 2019 Nil Foundation AG
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_MAC_COMPUTE_HPP
#define CRYPTO3_MAC_COMPUTE_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace mac {
            /*!
             * @defgroup mac Message Authentication Codes
             *
             * @brief A message authentication code (MAC) can be used to verify the
             * integrity of data and the authenticity of a message.
             *
             * @defgroup mac_algorithms Algorithms
             * @ingroup mac
             * @brief Algorithms are meant to provide message authentication codes computation
             * interface similar to STL algorithms' one.
             */

            namespace detail {
                template<typename Encoder, typename InputIterator, typename OutputIterator>
                OutputIterator compute_impl(InputIterator first, InputIterator last, OutputIterator out, Encoder pred) {
                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    pred.compute(first, last);

                    typename Encoder::result_type result = pred.get();

                    return std::move(result.begin(), result.end(), out);
                };
            }    // namespace detail

            /*!
             * @brief
             *
             * @tparam MessageAuthenticationCode
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             * @param sh
             * @return
             */
            template<typename Encoder, typename InputIterator, typename OutputIterator>
            OutputIterator compute(InputIterator first, InputIterator last, OutputIterator out,
                                   Encoder sh = Encoder()) {
                return detail::compute_impl<Encoder>(first, last, out, sh);
            };

            /*!
             * @brief
             *
             * @tparam Encoder
             * @tparam SinglePassRange
             * @tparam OutputIterator
             *
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Encoder, typename SinglePassRange, typename OutputIterator>
            OutputIterator compute(const SinglePassRange &rng, OutputIterator out, Encoder sh = Encoder()) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                return detail::compute_impl<Encoder>(boost::begin(rng), boost::end(rng), out, sh);
            };

            template<typename Encoder, typename OutputRange, typename SinglePassRange>
            OutputRange compute(const SinglePassRange &rng, Encoder sh = Encoder()) {
                BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));
                OutputRange range;

                detail::compute_impl<Encoder>(boost::begin(rng), boost::end(rng), boost::begin(range), sh);

                return range;
            };
        }    // namespace mac
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MAC_COMPUTE_HPP
