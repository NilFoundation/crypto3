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
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/block/cipher_state_preprocessor.hpp>
#include <nil/crypto3/block/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename Encrypter,
                     typename SinglePassRange> using range_stream_encrypter_traits = typename Encrypter::cipher_type::template stream_hash<
                    std::numeric_limits<
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                    std::numeric_limits<
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::is_signed>;

            template<typename Encrypter,
                     typename InputIterator> using itr_stream_encrypter_traits = typename Encrypter::cipher_type::template stream_hash<
                    std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                    std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_signed>;

            template<typename CipherState>
            struct ref_encrypter_impl {
                typedef CipherState cipher_state_type;

                ref_encrypter_impl(const cipher_state_type &stream_encrypter) : se(stream_encrypter) {

                }

                cipher_state_type &se;
            };

            template<typename CipherState>
            struct value_encrypter_impl {
                typedef CipherState cipher_state_type;

                value_encrypter_impl(const cipher_state_type &stream_encrypter) : se(stream_encrypter) {

                }

                mutable cipher_state_type se;
            };

            template<typename CipherStateImpl>
            struct range_encrypter_impl : public CipherStateImpl {
            public:
                typedef CipherStateImpl cipher_state_impl_type;
                typedef typename cipher_state_impl_type::cipher_state_type cipher_state_type;
                typedef typename cipher_state_type::mode_type mode_type;

                template<typename SinglePassRange>
                range_encrypter_impl(const SinglePassRange &range, const cipher_state_type &ish)
                        : CipherStateImpl(ish) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->se.insert(this->se.end(), range.begin(), range.end());
                }

                template<typename InputIterator>
                range_encrypter_impl(InputIterator first, InputIterator last, const cipher_state_type &ish)
                        : CipherStateImpl(ish) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->se.insert(this->se.end(), first, last);
                }

                template<typename OutputRange>
                operator OutputRange() const {
                    return OutputRange(this->se.begin(), this->se.end());
                }

                operator typename cipher_state_type::container_type() const {
                    return this->se.data();
                }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                template<typename Char, typename CharTraits, typename Alloc>
                operator std::basic_string<Char, CharTraits, Alloc>() const {
                    return std::to_string(this->se.data());
                }

#endif
            };

            template<typename CipherStateImpl, typename OutputIterator>
            struct itr_encrypter_impl : public CipherStateImpl {
            private:
                mutable OutputIterator out;

            public:
                typedef CipherStateImpl cipher_state_impl_type;
                typedef typename cipher_state_impl_type::cipher_state_type cipher_state_type;
                typedef typename cipher_state_type::mode_type mode_type;

                template<typename SinglePassRange>
                itr_encrypter_impl(const SinglePassRange &range, OutputIterator out, const cipher_state_type &ish)
                        : CipherStateImpl(ish), out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->se.insert(this->se.end(), range.begin(), range.end());
                }

                template<typename InputIterator>
                itr_encrypter_impl(InputIterator first, InputIterator last, OutputIterator out,
                                   const cipher_state_type &ish)
                        : CipherStateImpl(ish), out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->se.insert(this->se.end(), first, last);
                }

                operator OutputIterator() const {
                    return std::move(this->se.begin(), this->se.end(), out);
                }
            };
        }
    }
}

#endif //CRYPTO3_CODEC_POSTPROCESSOR_HPP
