//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CODEC_VALUE_HPP
#define CRYPTO3_CODEC_VALUE_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/codec/detail/digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            template<typename EncoderMode,
                     typename SinglePassRange> using range_stream_codec_traits = typename EncoderMode::encoder_type::template stream_processor<
                    EncoderMode, std::numeric_limits<
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                                 std::numeric_limits<typename std::iterator_traits<
                                         typename SinglePassRange::iterator>::value_type>::is_signed>;

            template<typename EncoderMode,
                     typename InputIterator> using itr_stream_codec_traits = typename EncoderMode::encoder_type::template stream_processor<
                    EncoderMode, std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                                 std::numeric_limits<
                                         typename std::iterator_traits<InputIterator>::value_type>::is_signed>;

            namespace detail {
                template<typename CodecState>
                struct ref_codec_impl {
                    typedef CodecState codec_state_type;

                    ref_codec_impl(const codec_state_type &codec_state) : se(codec_state) {

                    }

                    codec_state_type &se;
                };

                template<typename CodecState>
                struct value_codec_impl {
                    typedef CodecState codec_state_type;

                    value_codec_impl(const codec_state_type &codec_state) : se(codec_state) {

                    }

                    mutable codec_state_type se;
                };

                template<typename CodecStateImpl>
                struct range_codec_impl : public CodecStateImpl {
                    typedef CodecStateImpl codec_state_impl_type;
                    typedef typename codec_state_impl_type::codec_state_type codec_state_type;
                    typedef typename codec_state_type::mode_type mode_type;

                    template<typename SinglePassRange>
                    range_codec_impl(const SinglePassRange &range, const codec_state_type &ise)
                            : CodecStateImpl(ise) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->se.insert(this->se.end(), range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    range_codec_impl(InputIterator first, InputIterator last, const codec_state_type &ise)
                            : CodecStateImpl(ise) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->se.insert(this->se.end(), first, last);
                    }

                    template<typename OutputRange>
                    operator OutputRange() const {
                        if (mode_type::input_block_bits &&
                            this->se.preprocessor_state().seen % mode_type::input_block_bits) {
                            typename mode_type::finalizer_type(mode_type::input_block_bits -
                                                               this->se.preprocessor_state().seen %
                                                               mode_type::input_block_bits)(this->se);
                        } else {
                            typename mode_type::finalizer_type(0)(this->se);
                        }

                        return OutputRange(this->se.cbegin(), this->se.cend());
                    }

                    operator typename codec_state_type::container_type() const {
                        if (mode_type::input_block_bits &&
                            this->se.preprocessor_state().seen % mode_type::input_block_bits) {
                            typename mode_type::finalizer_type(mode_type::input_block_bits -
                                                               this->se.preprocessor_state().seen %
                                                               mode_type::input_block_bits)(this->se);
                        } else {
                            typename mode_type::finalizer_type(0)(this->se);
                        }

                        return this->se.data();
                    }

#ifdef CRYPTO3_ASCII_STRING_CODEC_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(this->result());
                    }

#endif
                };

                template<typename CodecStateImpl, typename OutputIterator>
                struct itr_codec_impl : public CodecStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef CodecStateImpl codec_state_impl_type;
                    typedef typename codec_state_impl_type::codec_state_type codec_state_type;
                    typedef typename codec_state_type::mode_type mode_type;

                    template<typename SinglePassRange>
                    itr_codec_impl(const SinglePassRange &range, OutputIterator out, const codec_state_type &ise)
                            : CodecStateImpl(ise), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->se.insert(this->se.end(), range.begin(), range.end());
                    }

                    template<typename InputIterator>
                    itr_codec_impl(InputIterator first, InputIterator last, OutputIterator out,
                                   const codec_state_type &ise)
                            : CodecStateImpl(ise), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->se.insert(this->se.end(), first, last);
                    }

                    operator OutputIterator() const {
                        if (mode_type::input_block_bits &&
                            this->se.preprocessor_state().seen % mode_type::input_block_bits) {
                            typename mode_type::finalizer_type(mode_type::input_block_bits -
                                                               this->se.preprocessor_state().seen %
                                                               mode_type::input_block_bits)(this->se);
                        } else {
                            typename mode_type::finalizer_type(0)(this->se);
                        }

                        return std::move(this->se.cbegin(), this->se.cend(), out);
                    }
                };
            }
        }
    }
}

#endif //CRYPTO3_CODEC_VALUE_HPP
