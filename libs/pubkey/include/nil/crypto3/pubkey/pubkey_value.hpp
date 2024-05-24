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

#ifndef CRYPTO3_PUBKEY_VALUE_HPP
#define CRYPTO3_PUBKEY_VALUE_HPP

#include <type_traits>
#include <iterator>

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/concepts.hpp>

#include <boost/mpl/front.hpp>
#include <boost/mpl/apply.hpp>

#include <nil/crypto3/pubkey/keys/agreement_key.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>
#include <nil/crypto3/pubkey/accumulators/parameters/key.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            namespace detail {
                template<typename SchemeAccumulator>
                struct ref_pubkey_impl {
                    typedef SchemeAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    ref_pubkey_impl(accumulator_set_type &&acc) : accumulator_set(acc) {
                    }

                    accumulator_set_type &accumulator_set;
                };

                template<typename SchemeAccumulator>
                struct value_pubkey_impl {
                    typedef SchemeAccumulator accumulator_set_type;
                    typedef
                        typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

                    value_pubkey_impl(accumulator_set_type &&acc) :
                        accumulator_set(std::forward<accumulator_set_type>(acc)) {
                    }

                    mutable accumulator_set_type accumulator_set;
                };

                template<typename SchemeStateImpl>
                struct range_pubkey_impl : public SchemeStateImpl {
                    typedef SchemeStateImpl scheme_state_impl_type;

                    typedef typename scheme_state_impl_type::accumulator_type accumulator_type;
                    typedef typename scheme_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    range_pubkey_impl(accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        this->accumulator_set();
                    }

                    template<typename SinglePassRange>
                    range_pubkey_impl(const SinglePassRange &range, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        this->accumulator_set(range);
                    }

                    template<typename InputIterator>
                    range_pubkey_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        this->accumulator_set(first, ::nil::crypto3::accumulators::iterator_last = last);
                    }

                    template<typename InputIterator1, typename InputIterator2>
                    range_pubkey_impl(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                      InputIterator2 last2, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator1>));
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator2>));

                        this->accumulator_set(first1, ::nil::crypto3::accumulators::iterator_last = last1);
                        this->accumulator_set(first2, ::nil::crypto3::accumulators::iterator_last = last2);
                    }

                    template<typename SinglePassRange, typename Scheme>
                    range_pubkey_impl(const SinglePassRange &range, accumulator_set_type &&ise,
                                      const public_key<Scheme> &pubkey) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                        this->accumulator_set(range, ::nil::crypto3::accumulators::key = pubkey);
                    }

                    template<typename InputIterator, typename Scheme>
                    range_pubkey_impl(InputIterator first, InputIterator last, accumulator_set_type &&ise,
                                      const public_key<Scheme> &pubkey) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        this->accumulator_set(first, ::nil::crypto3::accumulators::iterator_last = last,
                                              ::nil::crypto3::accumulators::key = pubkey);
                    }

                    // TODO: fix
                    template<typename Scheme>
                    range_pubkey_impl(accumulator_set_type &&ise,
                                      const typename public_key<Scheme>::signature_type &signature) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)) {
                        this->accumulator_set(signature);
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

                template<typename SchemeStateImpl, typename OutputIterator>
                struct itr_pubkey_impl : public SchemeStateImpl {
                private:
                    mutable OutputIterator out;

                public:
                    typedef SchemeStateImpl scheme_state_impl_type;

                    typedef typename scheme_state_impl_type::accumulator_type accumulator_type;
                    typedef typename scheme_state_impl_type::accumulator_set_type accumulator_set_type;

                    typedef typename boost::mpl::apply<accumulator_set_type, accumulator_type>::type::result_type
                        result_type;

                    itr_pubkey_impl(OutputIterator out, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)), out(std::move(out)) {
                    }

                    template<typename SinglePassRange>
                    itr_pubkey_impl(const SinglePassRange &range, OutputIterator out, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        this->accumulator_set(range);
                    }

                    template<typename InputIterator>
                    itr_pubkey_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        this->accumulator_set(first, ::nil::crypto3::accumulators::iterator_last = last);
                    }

                    template<typename InputIterator1, typename InputIterator2>
                    itr_pubkey_impl(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                    InputIterator2 last2, OutputIterator out, accumulator_set_type &&ise) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator1>));
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator2>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        this->accumulator_set(first1, ::nil::crypto3::accumulators::iterator_last = last1);
                        this->accumulator_set(first2, ::nil::crypto3::accumulators::iterator_last = last2);
                    }

                    template<typename SinglePassRange, typename Scheme>
                    itr_pubkey_impl(const SinglePassRange &range, OutputIterator out, accumulator_set_type &&ise,
                                    const public_key<Scheme> &pubkey) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        this->accumulator_set(range, ::nil::crypto3::accumulators::key = pubkey);
                    }

                    template<typename InputIterator, typename Scheme>
                    itr_pubkey_impl(InputIterator first, InputIterator last, OutputIterator out,
                                    accumulator_set_type &&ise, const public_key<Scheme> &pubkey) :
                        SchemeStateImpl(std::forward<accumulator_set_type>(ise)),
                        out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));
                        BOOST_CONCEPT_ASSERT((boost::OutputIteratorConcept<OutputIterator, result_type>));

                        this->accumulator_set(first, ::nil::crypto3::accumulators::iterator_last = last,
                                              ::nil::crypto3::accumulators::key = pubkey);
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

#endif    // CRYPTO3_PUBKEY_VALUE_HPP
