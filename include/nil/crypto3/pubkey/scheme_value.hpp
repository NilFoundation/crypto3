//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_CIPHER_VALUE_HPP
#define CRYPTO3_PUBKEY_CIPHER_VALUE_HPP

#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/mpl/front.hpp>
#include <boost/mpl/apply.hpp>

#include <nil/crypto3/pubkey/accumulators/sign.hpp>
#include <nil/crypto3/pubkey/accumulators/verify.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename PubkeyAccumulator>
                struct ref_scheme_impl {
                    typedef PubkeyAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::mode_type mode_type;
                    typedef typename mode_type::scheme_type scheme_type;

                    ref_scheme_impl(accumulator_set_type &&acc) : accumulator_set(acc) {
                    }

                    accumulator_set_type &accumulator_set;
                };

                template<typename PubkeyAccumulator>
                struct value_scheme_impl {
                    typedef PubkeyAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    typedef typename accumulator_type::mode_type mode_type;
                    typedef typename mode_type::scheme_type scheme_type;

                    value_scheme_impl(accumulator_set_type &&acc) :
                        accumulator_set(std::forward<accumulator_set_type>(acc)) {
                    }

                    mutable accumulator_set_type accumulator_set;
                };

                template<typename PubkeySchemeStateImpl>
                struct range_scheme_impl : public PubkeySchemeStateImpl {
                    typedef PubkeySchemeStateImpl pubkey_state_impl_type;

                    typedef typename pubkey_state_impl_type::accumulator_type accumulator_type;
                    typedef typename pubkey_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename pubkey_state_impl_type::mode_type mode_type;
                    typedef typename pubkey_state_impl_type::scheme_type scheme_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange,
                             typename ValueType =
                                 typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                             typename std::enable_if<std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    range_scheme_impl(const SinglePassRange &range, accumulator_set_type &&ise) :
                        PubkeySchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename scheme_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<ValueType>::digits + std::numeric_limits<ValueType>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator,
                             typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                             typename std::enable_if<std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    range_scheme_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise) :
                        PubkeySchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename scheme_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<ValueType>::digits + std::numeric_limits<ValueType>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    template<
                        typename SinglePassRange,
                        typename ValueType =
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                        typename std::enable_if<!std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    range_scheme_impl(const SinglePassRange &range, accumulator_set_type &&ise) :
                        PubkeySchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        typedef typename scheme_type::template stream_processor<mode_type, accumulator_set_type>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range);
                    }

                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<!std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    range_scheme_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise) :
                        PubkeySchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename scheme_type::template stream_processor<mode_type, accumulator_set_type>::type
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
                    operator OutputRange() const {
                        result_type result =
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return OutputRange(result.cbegin(), result.cend());
                    }

                    operator result_type() const {
                        return boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                    }

                    operator accumulator_set_type &() const {
                        return this->accumulator_set;
                    }

#ifdef CRYPTO3_ASCII_STRING_CODEC_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(
                            boost::accumulators::extract_result<accumulator_type>(this->accumulator_set));
                    }

#endif
                };

                template<typename PubkeyStateImpl, typename OutputIterator>
                struct itr_scheme_impl : public PubkeyStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef PubkeyStateImpl pubkey_state_impl_type;

                    typedef typename pubkey_state_impl_type::accumulator_type accumulator_type;
                    typedef typename pubkey_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename pubkey_state_impl_type::mode_type mode_type;
                    typedef typename pubkey_state_impl_type::scheme_type scheme_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    template<typename SinglePassRange,
                             typename ValueType =
                                 typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                             typename std::enable_if<std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    itr_scheme_impl(const SinglePassRange &range, OutputIterator out, accumulator_set_type &&ise) :
                        PubkeyStateImpl(std::forward<accumulator_set_type>(ise)), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        typedef typename scheme_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<ValueType>::digits + std::numeric_limits<ValueType>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range.begin(), range.end());
                    }

                    template<typename InputIterator,
                             typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                             typename std::enable_if<std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    itr_scheme_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    accumulator_set_type &&ise) :
                        PubkeyStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        typedef typename scheme_type::template stream_processor<
                            mode_type, accumulator_set_type,
                            std::numeric_limits<ValueType>::digits + std::numeric_limits<ValueType>::is_signed>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    template<
                        typename SinglePassRange,
                        typename ValueType =
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                        typename std::enable_if<!std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    itr_scheme_impl(const SinglePassRange &range, OutputIterator out, const accumulator_set_type &ise) :
                        PubkeyStateImpl(std::forward<accumulator_set_type>(ise)), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        typedef typename scheme_type::template stream_processor<mode_type, accumulator_set_type>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(range);
                    }

                    template<
                        typename InputIterator,
                        typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                        typename std::enable_if<!std::numeric_limits<ValueType>::is_specialized, bool>::type = true>
                    itr_scheme_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    accumulator_set_type &&ise) :
                        PubkeyStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        typedef typename scheme_type::template stream_processor<mode_type, accumulator_set_type>::type
                            stream_processor;

                        stream_processor(this->accumulator_set)(first, last);
                    }

                    operator OutputIterator() const {
                        *out++ = boost::accumulators::extract_result<accumulator_type>(this->accumulator_set);
                        return out;
                    }
                };
            }    // namespace detail
        }        // namespace pubkey
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_POSTPROCESSOR_HPP
