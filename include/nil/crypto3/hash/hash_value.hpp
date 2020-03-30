//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP
#define CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <nil/crypto3/hash/accumulators/hash.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename HashAccumulatorSet>
                struct ref_hash_impl {
                    typedef HashAccumulatorSet accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::hash_type hash_type;

                    ref_hash_impl(accumulator_set_type &&stream_hash) : accumulator_set(stream_hash) {
                    }

                    accumulator_set_type &accumulator_set;
                };

                template<typename HashAccumulatorSet>
                struct value_hash_impl {
                    typedef HashAccumulatorSet accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::hash_type hash_type;

                    value_hash_impl(accumulator_set_type &&stream_hash) :
                        accumulator_set(std::forward<accumulator_set_type>(stream_hash)) {
                    }

                    mutable accumulator_set_type accumulator_set;
                };

                template<typename HashStateImpl>
                struct range_hash_impl : public HashStateImpl {
                    typedef HashStateImpl hash_state_impl_type;

                    typedef typename hash_state_impl_type::accumulator_type accumulator_type;
                    typedef typename hash_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename hash_state_impl_type::hash_type hash_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    range_hash_impl(const SinglePassRange &range, accumulator_set_type &&ise) :
                        HashStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename hash_type::template stream_processor<
                            accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    range_hash_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise) :
                        HashStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename hash_type::template stream_processor<
                            accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    template<typename T, std::size_t Size>
                    inline operator std::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        std::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.end());
                        return out;
                    }

                    template<typename T, std::size_t Size>
                    inline operator boost::array<T, Size>() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        boost::array<T, Size> out;
                        std::copy(result.begin(), result.end(), out.end());
                        return out;
                    }

                    template<typename OutputRange>
                    inline operator OutputRange() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return OutputRange(result.begin(), result.end());
                    }

                    inline operator result_type() const {
                        return boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                    }

                    inline operator accumulator_set_type &() const {
                        return this->accumulator_set;
                    }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    inline operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set));
                    }

#endif
                };

                template<typename HashStateImpl, typename OutputIterator>
                struct itr_hash_impl : public HashStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef HashStateImpl hash_state_impl_type;

                    typedef typename hash_state_impl_type::accumulator_type accumulator_type;
                    typedef typename hash_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename hash_state_impl_type::hash_type hash_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange>
                    itr_hash_impl(const SinglePassRange &range, OutputIterator out, accumulator_set_type &&ise) :
                        HashStateImpl(std::forward<accumulator_set_type>(ise)), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename hash_type::template stream_processor<
                            accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    itr_hash_impl(InputIterator first, InputIterator last, OutputIterator out,
                                  accumulator_set_type &&ise) :
                        HashStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename hash_type::template stream_processor<
                            accumulator_set_type,
                            std::numeric_limits<value_type>::digits + std::numeric_limits<value_type>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    inline operator accumulator_set_type &() const {
                        return this->accumulator_set;
                    }

                    inline operator OutputIterator() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return std::move(result.cbegin(), result.cend(), out);
                    }
                };
            }    // namespace detail
        }        // namespace hash
    }            // namespace crypto3
}    // namespace nil

#endif
