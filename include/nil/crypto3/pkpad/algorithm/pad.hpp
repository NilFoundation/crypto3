#ifndef CRYPTO3_PUBKEY_PAD_HPP
#define CRYPTO3_PUBKEY_PAD_HPP

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
                    template<typename PaddingPolicy, typename UniformRandomBitGenerator,
                             typename RandomNumberDistribution, typename InputIterator, typename OutputIterator>
                    inline OutputIterator pad_impl(InputIterator first, InputIterator last, OutputIterator result,
                                                   std::size_t key_length, UniformRandomBitGenerator rand,
                                                   RandomNumberDistribution dist, PaddingPolicy pred) {
                        return pred.pad(first, last, result, key_length, rand, dist);
                    }

                    template<typename PaddingPolicy, typename UniformRandomBitGenerator,
                             typename RandomNumberDistribution, typename InputIterator1, typename InputIterator2,
                             typename OutputIterator>
                    inline OutputIterator pad_impl(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                                   InputIterator2 last2, OutputIterator result, std::size_t key_length,
                                                   UniformRandomBitGenerator rand, RandomNumberDistribution dist,
                                                   PaddingPolicy pred) {
                        return pred.pad(first1, last1, first2, last2, result, key_length, rand, dist);
                    }
                }    // namespace detail

                /*!
                 * @brief
                 * @tparam PaddingPolicy
                 * @tparam UniformRandomBitGenerator
                 * @tparam SinglePassRange
                 * @tparam OutputIterator
                 * @param rng
                 * @param out
                 * @param rand
                 * @param fun
                 * @return
                 *
                 * @pre SinglePassRange is a model of the SinglePassRangeConcept
                 * @pre OutputIterator is a model of the OutputIteratorConcept
                 * @pre Predicate is a model of the UnaryFunctionConcept
                 * @pre BinaryOperation is a model of the BinaryFunctionConcept
                 */
                template<typename PaddingPolicy, typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                         typename SinglePassRange, typename OutputIterator,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange>::value>::type>
                OutputIterator pad(const SinglePassRange &rng, OutputIterator out, std::size_t key_length,
                                   UniformRandomBitGenerator rand, RandomNumberDistribution dist,
                                   PaddingPolicy fun = PaddingPolicy()) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    return detail::pad_impl<PaddingPolicy>(boost::begin(rng), boost::end(rng), out, key_length, rand,
                                                           dist, fun);
                }

                /*!
                 *
                 * @tparam PaddingPolicy
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
                template<typename PaddingPolicy, typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                         typename SinglePassRange1, typename SinglePassRange2, typename OutputIterator,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange1>::value>::type,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange2>::value>::type>

                OutputIterator pad(const SinglePassRange1 &rng1, const SinglePassRange2 &rng2, OutputIterator out,
                                   std::size_t key_length, UniformRandomBitGenerator rand,
                                   RandomNumberDistribution dist, PaddingPolicy fun = PaddingPolicy()) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange1>));
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange2>));

                    return detail::pad_impl<PaddingPolicy>(boost::begin(rng1), boost::end(rng1), boost::begin(rng2),
                                                           boost::end(rng2), out, key_length, rand, dist, fun);
                }

                /*!
                 *
                 * @tparam PaddingPolicy
                 * @tparam InputIterator
                 * @tparam OutputIterator
                 * @tparam Predicate
                 * @param first
                 * @param last
                 * @param result
                 * @param pred
                 * @return
                 */
                template<typename PaddingPolicy, typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                         typename InputIterator, typename OutputIterator>
                OutputIterator pad(InputIterator first, InputIterator last, OutputIterator result,
                                   std::size_t key_length, UniformRandomBitGenerator rand,
                                   RandomNumberDistribution dist, PaddingPolicy pred = PaddingPolicy()) {
                    return detail::pad_impl<PaddingPolicy>(first, last, result, key_length, rand, dist, pred);
                }

                /*!
                 *
                 * @tparam PaddingPolicy
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
                template<typename PaddingPolicy, typename UniformRandomBitGenerator, typename RandomNumberDistribution,
                         typename InputIterator1, typename InputIterator2, typename OutputIterator>
                OutputIterator pad(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                   InputIterator2 last2, OutputIterator result, std::size_t key_length,
                                   UniformRandomBitGenerator rand, RandomNumberDistribution dist,
                                   PaddingPolicy pred = PaddingPolicy()) {
                    return detail::pad_impl<PaddingPolicy>(first1, last1, first2, last2, result, key_length, rand, dist,
                                                           pred);
                }
            }    // namespace padding
        }        // namespace public_key
    }            // namespace crypto3
}    // namespace nil

#endif    // include guard
