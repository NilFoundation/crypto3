//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP
#define CRYPTO3_HASH_STREAM_POSTPROCESSOR_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/hash/detail/type_traits.hpp>
#include <nil/crypto3/hash/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            namespace detail {
                template<typename StreamHash>
                struct ref_hash_impl {
                    typedef StreamHash stream_hash_type;

                    ref_hash_impl(const StreamHash &stream_hash) : sh(std::move(stream_hash)) {

                    }

                    template<typename Result>
                    Result result() const {
                        return sh.digest();
                    }

                    StreamHash &sh;
                };

                template<typename StreamHash>
                struct value_hash_impl {
                    typedef StreamHash stream_hash_type;

                    value_hash_impl(const StreamHash &stream_hash) : sh(stream_hash) {

                    }

                    template<typename Result>
                    Result result() const {
                        return sh.end_message();
                    }

                    mutable StreamHash sh;
                };

                template<typename Hasher, typename StreamHashImpl>
                struct range_hash_impl : public StreamHashImpl {
                public:
                    template<typename SinglePassRange>
                    range_hash_impl(const SinglePassRange &range, const typename StreamHashImpl::stream_hash_type &ish)
                            : StreamHashImpl(ish) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->sh(boost::begin(range), boost::end(range));
                    }

                    template<typename InputIterator>
                    range_hash_impl(InputIterator first, InputIterator last,
                                    const typename StreamHashImpl::stream_hash_type &ish) : StreamHashImpl(ish) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->sh(first, last);
                    }

                    template<typename OutputRange>
                    operator OutputRange() const {
                        const auto &range = this->template result<typename Hasher::digest_type>();

                        return OutputRange(range.begin(), range.end());
                    }

                    operator typename Hasher::digest_type() const {
                        return this->template result<typename Hasher::digest_type>();
                    }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return std::to_string(this->template result<typename Hasher::digest_type>());
                    }

#endif
                };

                template<typename Hasher, typename StreamHashImpl, typename OutputIterator>
                struct itr_hash_impl : public StreamHashImpl {
                private:
                    mutable OutputIterator out;

                public:
                    template<typename SinglePassRange>
                    itr_hash_impl(const SinglePassRange &range, OutputIterator out,
                                  const typename StreamHashImpl::stream_hash_type &ish) : StreamHashImpl(ish),
                            out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                        typedef typename std::iterator_traits<
                                typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->sh(boost::begin(range), boost::end(range));
                    }

                    template<typename InputIterator>
                    itr_hash_impl(InputIterator first, InputIterator last, OutputIterator out,
                                  const typename StreamHashImpl::stream_hash_type &ish)
                            : StreamHashImpl(ish), out(std::move(out)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        this->sh(first, last);
                    }

                    operator OutputIterator() const {
                        const auto &result = this->template result<typename Hasher::digest_type>();

                        return std::move(result.begin(), result.end(), out);
                    }
                };
            }
        }
    }
}

#endif
