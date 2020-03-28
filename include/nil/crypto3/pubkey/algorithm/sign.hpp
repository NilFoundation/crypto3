//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_SIGN_HPP
#define CRYPTO3_PUBKEY_SIGN_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/core/enable_if.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>
#include <boost/range/any_range.hpp>

#include <nil/crypto3/detail/static_digest.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @addtogroup sign_algorithms Algorithms
         * @addtogroup sign
         * @brief Algorithms are meant to provide signing interface similar to STL algorithms' one.
         */

        namespace detail {
            template<typename Signer, typename SinglePassRange>
            using range_stream_sign_traits = typename Signer::template stream_sign<
                std::numeric_limits<
                    typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                std::numeric_limits<
                    typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::is_signed>;

            template<typename Signer, typename InputIterator>
            using itr_stream_sign_traits = typename Signer::template stream_sign<
                std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_signed>;

            template<typename StreamSigner>
            struct ref_sign_impl {
                typedef StreamSigner stream_sign_type;

                ref_sign_impl(const StreamSigner &stream_sign) : sh(std::move(stream_sign)) {
                }

                template<typename Result>
                Result result() const {
                    return sh.digest();
                }

                StreamSigner &sh;
            };

            template<typename StreamSigner>
            struct value_sign_impl {
                typedef StreamSigner stream_sign_type;

                value_sign_impl(const StreamSigner &stream_sign) : sh(stream_sign) {
                }

                template<typename Result>
                Result result() const {
                    return sh.end_message();
                }

                mutable StreamSigner sh;
            };

            template<typename Signer, typename StreamSignerImpl>
            struct range_sign_impl : public StreamSignerImpl {
            public:
                template<typename SinglePassRange>
                range_sign_impl(const SinglePassRange &range, const typename StreamSignerImpl::stream_sign_type &ish) :
                    StreamSignerImpl(ish) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(boost::begin(range), boost::end(range));
                }

                template<typename InputIterator>
                range_sign_impl(InputIterator first, InputIterator last,
                                const typename StreamSignerImpl::stream_sign_type &ish) :
                    StreamSignerImpl(ish) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(first, last);
                }

                template<typename OutputRange>
                operator OutputRange() const {
                    const auto &range = this->template result<typename Signer::digest_type>();

                    return OutputRange(range.begin(), range.end());
                }

                operator typename Signer::digest_type() const {
                    return this->template result<typename Signer::digest_type>();
                }

#ifndef CRYPTO3_RAW_PUBKEY_STRING_OUTPUT

                template<typename Char, typename CharTraits, typename Alloc>
                operator std::basic_string<Char, CharTraits, Alloc>() const {
                    return std::to_string(this->template result<typename Signer::digest_type>());
                }

#endif
            };

            template<typename Signer, typename StreamSignerImpl, typename OutputIterator>
            struct itr_sign_impl : public StreamSignerImpl {
            private:
                mutable OutputIterator out;

            public:
                template<typename SinglePassRange>
                itr_sign_impl(const SinglePassRange &range, OutputIterator out,
                              const typename StreamSignerImpl::stream_sign_type &ish) :
                    StreamSignerImpl(ish),
                    out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(boost::begin(range), boost::end(range));
                }

                template<typename InputIterator>
                itr_sign_impl(InputIterator first, InputIterator last, OutputIterator out,
                              const typename StreamSignerImpl::stream_sign_type &ish) :
                    StreamSignerImpl(ish),
                    out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(first, last);
                }

                operator OutputIterator() const {
                    const auto &result = this->template result<typename Signer::digest_type>();

                    return std::move(result.begin(), result.end(), out);
                }
            };
        }    // namespace detail

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamSigner
         *
         * @param first
         * @param last
         * @param out
         *
         * @return
         */
        template<typename Signer, typename InputIterator, typename KeyIterator, typename OutputIterator,
                 typename StreamSigner = typename detail::itr_stream_sign_traits<Signer, InputIterator>::type>
        OutputIterator sign(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last,
                            OutputIterator out) {

            typedef detail::value_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::itr_sign_impl<Signer, StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), StreamSigner(Signer(key_first, key_last)));
        };

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam InputIterator
         * @tparam OutputIterator
         * @tparam StreamSigner
         * @param first
         * @param last
         * @param out
         * @param sh
         * @return
         */
        template<typename Signer, typename InputIterator, typename OutputIterator,
                 typename StreamSigner = typename detail::itr_stream_sign_traits<Signer, InputIterator>::type>
        OutputIterator sign(InputIterator first, InputIterator last, const private_key<Signer> &pk,
                            OutputIterator out) {

            typedef detail::ref_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::itr_sign_impl<Signer, StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(first, last, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam InputIterator
         * @tparam StreamSigner
         * @param first
         * @param last
         * @return
         */
        template<typename Signer, typename InputIterator, typename KeyIterator,
                 typename StreamSigner = typename detail::itr_stream_sign_traits<Signer, InputIterator>::type>
        detail::range_sign_impl<Signer, detail::value_sign_impl<StreamSigner>>
            sign(InputIterator first, InputIterator last, KeyIterator key_first, KeyIterator key_last) {
            typedef detail::value_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::range_sign_impl<Signer, StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, StreamSigner(Signer(key_first, key_last)));
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam InputIterator
         * @tparam StreamSigner
         * @param first
         * @param last
         * @param sh
         * @return
         */
        template<typename Signer, typename InputIterator,
                 typename StreamSigner = typename detail::itr_stream_sign_traits<Signer, InputIterator>::type>
        detail::range_sign_impl<Signer, detail::ref_sign_impl<StreamSigner>>
            sign(InputIterator first, InputIterator last, const private_key<Signer> &pk) {
            typedef detail::ref_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::range_sign_impl<Signer, StreamSignerImpl> SignerImpl;

            return SignerImpl(first, last, sh);
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamSigner
         * @param rng
         * @param out
         * @return
         */
        template<typename Signer, typename SinglePassRange, typename KeyRange, typename OutputIterator,
                 typename StreamSigner = typename detail::range_stream_sign_traits<Signer, SinglePassRange>::type>
        OutputIterator sign(const SinglePassRange &rng, const KeyRange &key, OutputIterator out) {

            typedef detail::value_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::itr_sign_impl<Signer, StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), StreamSigner());
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam SinglePassRange
         * @tparam OutputIterator
         * @tparam StreamSigner
         * @param rng
         * @param out
         * @param sh
         * @return
         */
        template<typename Signer, typename SinglePassRange, typename OutputIterator,
                 typename StreamSigner = typename detail::range_stream_sign_traits<Signer, SinglePassRange>::type>
        OutputIterator sign(const SinglePassRange &rng, OutputIterator out, const private_key<Signer> &pk) {

            typedef detail::ref_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::itr_sign_impl<Signer, StreamSignerImpl, OutputIterator> SignerImpl;

            return SignerImpl(rng, std::move(out), sh);
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam SinglePassRange
         * @tparam StreamSigner
         * @param r
         * @return
         */
        template<typename Signer, typename SinglePassRange, typename KeyRange,
                 typename StreamSigner = typename detail::range_stream_sign_traits<Signer, SinglePassRange>::type>
        detail::range_sign_impl<Signer, detail::value_sign_impl<StreamSigner>> sign(const SinglePassRange &r,
                                                                                    const KeyRange &key) {

            typedef detail::value_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::range_sign_impl<Signer, StreamSignerImpl> SignerImpl;

            return SignerImpl(r, StreamSigner());
        }

        /*!
         * @brief
         *
         * @addtogroup sign_algorithms
         *
         * @tparam Signer
         * @tparam SinglePassRange
         * @tparam StreamSigner
         * @param rng
         * @param sh
         * @return
         */
        template<typename Signer, typename SinglePassRange,
                 typename StreamSigner = typename detail::range_stream_sign_traits<Signer, SinglePassRange>::type>
        detail::range_sign_impl<Signer, detail::ref_sign_impl<StreamSigner>> sign(const SinglePassRange &rng,
                                                                                  const private_key<Signer> &pk) {
            typedef detail::ref_sign_impl<StreamSigner> StreamSignerImpl;
            typedef detail::range_sign_impl<Signer, StreamSignerImpl> SignerImpl;

            return SignerImpl(rng, sh);
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // include guard