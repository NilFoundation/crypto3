#ifndef CRYPTO3_UNPAD_HPP
#define CRYPTO3_UNPAD_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {
        namespace public_key {
            namespace padding {
                namespace detail {
                    template<typename UnpaddingPolicy, typename InputIterator, typename OutputIterator,
                             typename Predicate>
                    inline OutputIterator unpad_impl(InputIterator first, InputIterator last, OutputIterator result,
                                                     Predicate pred) {
                        return UnpaddingPolicy()(first, last, result, pred);
                    }

                    template<typename UnpaddingPolicy, typename InputIterator1, typename InputIterator2,
                             typename OutputIterator, typename Predicate>
                    inline OutputIterator unpad_impl(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                                     InputIterator2 last2, OutputIterator result, Predicate pred) {
                        return UnpaddingPolicy()(first1, last1, first2, last2, result, pred);
                    }
                }    // namespace detail

                /*! @brief template function unpad
                 *
                 * Range-based version of the unpad std algorithm
                 *
                 * @pre SinglePassRange is a model of the SinglePassRangeConcept
                 * @pre SinglePassRange2 is a model of the SinglePassRangeConcept
                 * @pre OutputIterator is a model of the OutputIteratorConcept
                 * @pre Predicate is a model of the UnaryFunctionConcept
                 * @pre BinaryOperation is a model of the BinaryFunctionConcept
                 */
                template<typename UnpaddingPolicy, typename SinglePassRange, typename OutputIterator,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange>::value>::type>
                OutputIterator unpad(const SinglePassRange &rng, OutputIterator out,
                                     UnpaddingPolicy fun = UnpaddingPolicy()) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));
                    return detail::unpad_impl(boost::begin(rng), boost::end(rng), out, fun);
                }

                /*!
                 *
                 * @tparam UnpaddingPolicy
                 * @tparam SinglePassRange1
                 * @tparam SinglePassRange2
                 * @tparam OutputIterator
                 * @tparam Predicate
                 * @param rng1
                 * @param rng2
                 * @param out
                 * @param fun
                 * @return
                 */
                template<typename UnpaddingPolicy, typename SinglePassRange1, typename SinglePassRange2,
                         typename OutputIterator,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange1>::value>::type,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange2>::value>::type>
                OutputIterator unpad(const SinglePassRange1 &rng1, const SinglePassRange2 &rng2, OutputIterator out,
                                     UnpaddingPolicy fun = UnpaddingPolicy()) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange1>));
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange2>));

                    return detail::unpad_impl(boost::begin(rng1), boost::end(rng1), boost::begin(rng2),
                                              boost::end(rng2), out, fun);
                }

                /*!
                 *
                 * @tparam UnpaddingPolicy
                 * @tparam InputIterator
                 * @tparam OutputIterator
                 * @tparam Predicate
                 * @param first
                 * @param last
                 * @param result
                 * @param pred
                 * @return
                 */
                template<typename UnpaddingPolicy, typename InputIterator, typename OutputIterator>
                OutputIterator unpad(InputIterator first, InputIterator last, OutputIterator result,
                                     UnpaddingPolicy pred = UnpaddingPolicy()) {
                    return detail::unpad_impl<UnpaddingPolicy>(first, last, result, pred);
                }

                /*!
                 *
                 * @tparam UnpaddingPolicy
                 * @tparam InputIterator1
                 * @tparam InputIterator2
                 * @tparam OutputIterator
                 * @tparam Predicate
                 * @param first1
                 * @param last1
                 * @param first2
                 * @param last2
                 * @param result
                 * @param pred
                 * @return
                 */
                template<typename UnpaddingPolicy, typename InputIterator1, typename InputIterator2,
                         typename OutputIterator>
                OutputIterator unpad(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                     InputIterator2 last2, OutputIterator result,
                                     UnpaddingPolicy pred = UnpaddingPolicy()) {
                    return detail::unpad_impl<UnpaddingPolicy>(first1, last1, first2, last2, result, pred);
                }
            }    // namespace padding
        }        // namespace public_key
    }            // namespace crypto3
}    // namespace nil

#endif    // include guard
