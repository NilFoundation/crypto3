//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CIPHER_VALUE_HPP
#define CRYPTO3_CIPHER_VALUE_HPP

#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/block/accumulators/block.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            namespace detail {
                template<typename CodecAccumulator>
                struct ref_cipher_impl {
                    typedef CodecAccumulator cipher_accumulator_type;
                    typedef typename cipher_accumulator_type::type cipher_accumulator_set;

                    typedef typename CodecAccumulator::mode_type mode_type;
                    typedef typename mode_type::encoder_type cipher_type;

                    ref_cipher_impl(const cipher_accumulator_set &acc) : accumulator_set(acc) {

                    }

                    cipher_accumulator_set &accumulator_set;
                };

                template<typename CodecAccumulator>
                struct value_cipher_impl {
                    typedef CodecAccumulator cipher_accumulator_type;
                    typedef typename cipher_accumulator_type::type cipher_accumulator_set;

                    typedef typename CodecAccumulator::mode_type mode_type;
                    typedef typename mode_type::encoder_type cipher_type;

                    value_cipher_impl(const cipher_accumulator_set &acc) : accumulator_set(acc) {

                    }

                    mutable cipher_accumulator_set accumulator_set;
                };

                template<typename CodecStateImpl>
                struct range_cipher_impl : public CodecStateImpl {
                    typedef CodecStateImpl cipher_state_impl_type;

                    typedef typename cipher_state_impl_type::cipher_accumulator_type cipher_accumulator_type;
                    typedef typename cipher_accumulator_type::type cipher_accumulator_set;

                    typedef typename cipher_state_impl_type::mode_type mode_type;
                    typedef typename cipher_state_impl_type::cipher_type cipher_type;

                    typedef typename boost::mpl::apply<cipher_accumulator_set, accumulators::tag::block<
                            mode_type> >::type::result_type result_type;

                    template<typename SinglePassRange>
                    range_cipher_impl(const SinglePassRange &range, const cipher_accumulator_set &ise)
                            : CodecStateImpl(ise) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<mode_type, cipher_accumulator_set,
                                                                                std::numeric_limits<
                                                                                        value_type>::digits +
                                                                                std::numeric_limits<
                                                                                        value_type>::is_signed>::type stream_processor;


                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    range_cipher_impl(InputIterator first, InputIterator last, const cipher_accumulator_set &ise)
                            : CodecStateImpl(ise) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<mode_type, cipher_accumulator_set,
                                                                                std::numeric_limits<
                                                                                        value_type>::digits +
                                                                                std::numeric_limits<
                                                                                        value_type>::is_signed>::type stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    template<typename OutputRange>
                    operator OutputRange() const {
                        result_type result = accumulators::extract::block<mode_type>(this->accumulator_set);
                        return OutputRange(result.cbegin(), result.cend());
                    }

                    operator result_type() const {
                        return accumulators::extract::block<mode_type>(this->accumulator_set);
                    }

                    operator cipher_accumulator_set() const {
                        return this->accumulator_set;
                    }

#ifdef CRYPTO3_ASCII_STRING_CODEC_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(accumulators::extract::cipher<mode_type>(this->accumulator_set));
                    }

#endif
                };

                template<typename CodecStateImpl, typename OutputIterator>
                struct itr_cipher_impl : public CodecStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef CodecStateImpl cipher_state_impl_type;

                    typedef typename cipher_state_impl_type::cipher_accumulator_type cipher_accumulator_type;
                    typedef typename cipher_accumulator_type::type cipher_accumulator_set;

                    typedef typename cipher_state_impl_type::mode_type mode_type;
                    typedef typename cipher_state_impl_type::cipher_type cipher_type;

                    typedef typename boost::mpl::apply<cipher_accumulator_set, accumulators::tag::block<
                            mode_type> >::type::result_type result_type;

                    template<typename SinglePassRange>
                    itr_cipher_impl(const SinglePassRange &range, OutputIterator out, const cipher_accumulator_set &ise)
                            : CodecStateImpl(ise), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<mode_type, cipher_accumulator_set,
                                                                                std::numeric_limits<
                                                                                        value_type>::digits +
                                                                                std::numeric_limits<
                                                                                        value_type>::is_signed>::type stream_processor;


                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    itr_cipher_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    const cipher_accumulator_set &ise)
                            : CodecStateImpl(ise), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;
                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);
                        typedef typename cipher_type::template stream_processor<mode_type, cipher_accumulator_set,
                                                                                std::numeric_limits<
                                                                                        value_type>::digits +
                                                                                std::numeric_limits<
                                                                                        value_type>::is_signed>::type stream_processor;


                        stream_processor(this->accumulator_set)(first, last);
                    }

                    operator OutputIterator() const {
                        result_type result = accumulators::extract::block<mode_type>(this->accumulator_set);

                        return std::move(result.cbegin(), result.cend(), out);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_CODEC_POSTPROCESSOR_HPP
