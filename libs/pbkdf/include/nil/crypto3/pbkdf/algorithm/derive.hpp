//---------------------------------------------------------------------------//
//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_PBKDF_HPP
#define CRYPTO3_PBKDF_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>

#include <boost/core/enable_if.hpp>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>
#include <boost/range/any_range.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        namespace pbkdf {
            /*!
             * @defgroup pbkdf Password Based Key Derivation Functions
             *
             * @brief There are various procedures for turning a passphrase into a arbitrary
             * length key for use with a symmetric cipher. A general interface for
             * such algorithms is presented in ``pbkdf.h``. The main function is
             * ``derive_key``, which takes a passphrase, a salt, an iteration count,
             * and the desired length of the output key, and returns a key of that
             * length, deterministically produced from the passphrase and salt. If an
             * algorithm can't produce a key of that size, it will throw an exception
             * (most notably, PKCS #5's PBKDF1 can only produce strings between 1 and
             * $n$ bytes, where $n$ is the output size of the underlying hash
             * function).
             *
             * The purpose of the iteration count is to make the algorithm take
             * longer to compute the final key (reducing the speed of brute-force
             * attacks of various kinds). Most standards recommend an iteration count
             * of at least 10000. Currently defined PBKDF algorithms are
             * "PBKDF1(static_digest)", "PBKDF2(static_digest)"; you can retrieve any of these
             * using the ``get_pbkdf``, found in ``lookup.h``. As of this writing,
             * "PBKDF2(SHA-256)" with at least 100000 iterations and a 16 byte salt
             * is recommend for new applications.
             *
             * @defgroup pbkdf_algorithms Algorithms
             * @ingroup pbkdf
             * @brief Algorithms are meant to provide key derivation interface similar to STL algorithms' one.
             */

            namespace detail {
                template<typename Hasher, typename SinglePassRange>
                using range_stream_hash_traits = typename Hasher::template stream_hash<
                    std::numeric_limits<
                        typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                    std::numeric_limits<typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::
                        is_signed>::type;

                template<typename Hasher, typename InputIterator>
                using iterator_stream_hash_traits = typename Hasher::template stream_hash<
                    std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                    std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type;

#ifdef CRYPTO3_RAW_PBKDF_STRING_OUTPUT

                template<typename Hash, typename InputIterator, typename StreamHasher>
                typename Hash::digest_type hash_impl_f(InputIterator first, InputIterator last,
                                                       StreamHasher accumulator) {
                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    return accumulator.update(first, last).end_message();
                };

                template<typename Hash, typename SinglePassRange, typename StreamHasher,
                         typename = typename std::enable_if<boost::has_range_iterator<SinglePassRange>::value>::type>
                typename Hash::digest_type hash_impl_f(const SinglePassRange &rng, StreamHasher accumulator) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    return accumulator.update(boost::begin(rng), boost::end(rng)).end_message();
                }
#else

                struct hash_impl {};

                template<typename Hasher, typename StreamHash>
                struct range_value_hash_impl : public hash_impl {
                private:
                    mutable StreamHash sh;

                public:
                    template<typename SinglePassRange>
                    range_value_hash_impl(const SinglePassRange &range, StreamHash stream_hash) :
                        sh(std::move(stream_hash)) {
                        BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        sh.update(boost::begin(range), boost::end(range));
                    }

                    template<typename OutputRange>
                    operator OutputRange() const {
                        typename Hasher::digest_type range = sh.end_message();

                        return OutputRange(range.begin(), range.end());
                    }

                    operator typename Hasher::digest_type() const {
                        return sh.end_message();
                    }

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return sh.end_message().str();
                    }
                };

                template<typename Hasher, typename OutputIterator, typename StreamHash>
                struct range_itr_hash_impl : public hash_impl {
                private:
                    mutable StreamHash sh;

                    mutable OutputIterator out;

                public:
                    template<typename SinglePassRange>
                    range_itr_hash_impl(const SinglePassRange &range, OutputIterator out, StreamHash stream_hash) :
                        out(std::move(out)), sh(std::move(stream_hash)) {
                        BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                        typedef
                            typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        sh.update(boost::begin(range), boost::end(range));
                    }

                    operator OutputIterator() const {
                        const auto &result = sh.end_message();

                        return std::move(result.begin(), result.end(), std::move(out));
                    }
                };

                template<typename Hasher, typename OutputIterator, typename StreamHash>
                struct itr_itr_hash_impl : public hash_impl {
                private:
                    mutable StreamHash sh;

                    mutable OutputIterator out;

                public:
                    template<typename InputIterator>
                    explicit itr_itr_hash_impl(InputIterator first, InputIterator last, OutputIterator out,
                                               StreamHash stream_hash) :
                        out(std::move(out)),
                        sh(std::move(stream_hash)) {
                        BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                        typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                        BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                        sh.update(first, last);
                    }

                    operator OutputIterator() const {
                        const auto &result = sh.end_message();

                        return std::move(result.begin(), result.end(), std::move(out));
                    }
                };

                /*!
                 * @brief
                 * @tparam Hasher
                 * @tparam Input
                 * @note Such an implementation way is chosen because of no available ways to infer template by
                 * return type are available. So the type implicit conversion is the way.
                 */
                template<typename Hasher, typename Input>
                class hash {
                private:
                    const detail::hash_impl &impl;

                public:
                    template<typename OutputIterator, typename StreamHash>
                    explicit hash(Input first, Input last, OutputIterator out, StreamHash sh) :
                        impl(std::move(detail::itr_itr_hash_impl<Hasher, OutputIterator, StreamHash>(
                            first, last, std::move(out), std::move(sh)))) {
                    }

                    template<typename OutputIterator, typename StreamHash>
                    explicit hash(const Input &range, OutputIterator out, StreamHash sh) :
                        impl(std::move(detail::range_itr_hash_impl<Hasher, OutputIterator, StreamHash>(
                            range, std::move(out), std::move(sh)))) {
                    }

                    template<typename StreamHash>
                    explicit hash(const Input &range, StreamHash sh) :
                        impl(std::move(detail::range_value_hash_impl<Hasher, StreamHash>(range, sh))) {
                    }

                private:
                    template<typename OutputIterator,
                             typename std::enable_if<detail::is_iterator<OutputIterator>::value &&
                                                         detail::is_iterator<Input>::value,
                                                     bool>::type = false>
                    OutputIterator to() const {
                        return static_cast<const detail::itr_itr_hash_impl<
                            Hasher, OutputIterator, detail::iterator_stream_hash_traits<Hasher, Input>> &>(impl);
                    }

                    template<typename OutputIterator,
                             typename std::enable_if<detail::is_iterator<OutputIterator>::value &&
                                                         !detail::is_iterator<Input>::value,
                                                     bool>::type = false>
                    OutputIterator to() const {
                        return static_cast<const detail::range_itr_hash_impl<
                            Hasher, OutputIterator, detail::range_stream_hash_traits<Hasher, Input>> &>(impl);
                    }

                    template<typename OutputRange, typename std::enable_if<!detail::is_iterator<Input>::value &&
                                                                               !detail::is_iterator<OutputRange>::value,
                                                                           bool>::type = false>
                    OutputRange to() const {
                        return static_cast<const detail::range_value_hash_impl<
                            Hasher, detail::range_stream_hash_traits<Hasher, Input>> &>(impl);
                    }

                public:
                    template<typename Output>
                    operator Output() const {
                        return to<Output>();
                    }

                    template<typename Char, typename CharTraits, typename Alloc>
                    operator std::basic_string<Char, CharTraits, Alloc>() const {
                        return static_cast<const detail::range_value_hash_impl<
                            Hasher, detail::range_stream_hash_traits<Hasher, Input>> &>(impl);
                    }
                };

#endif
            }    // namespace detail

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam StreamHash
             * @param first
             * @param last
             * @param out
             * @param sh
             * @return
             */
            template<typename Hasher, typename InputIterator, typename OutputIterator,
                     typename StreamHash = detail::iterator_stream_hash_traits<Hasher, InputIterator>,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out,
                                StreamHash sh = StreamHash()) {
                return detail::hash<Hasher, InputIterator>(first, last, std::move(out), std::move(sh));
            };

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam StreamHash
             * @param first
             * @param last
             * @param sh
             * @return
             */
            template<typename Hasher, typename InputIterator,
                     typename StreamHash = detail::iterator_stream_hash_traits<Hasher, InputIterator>,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::hash<Hasher, InputIterator> hash(InputIterator first, InputIterator last,
                                                     StreamHash sh = StreamHash()) {
                return detail::hash<Hasher, InputIterator>(boost::any_range(first, last), std::move(sh));
            };

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam StreamHash
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Hasher, typename SinglePassRange, typename OutputIterator,
                     typename StreamHash = detail::range_stream_hash_traits<Hasher, SinglePassRange>,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(const SinglePassRange &rng, OutputIterator out, StreamHash sh = StreamHash()) {
                return detail::hash<Hasher, SinglePassRange>(rng, std::move(out), std::move(sh));
            };

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam StreamHash
             * @param rng
             * @param sh
             * @return
             */
            template<typename Hasher, typename SinglePassRange,
                     typename StreamHash = detail::range_stream_hash_traits<Hasher, SinglePassRange>,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::hash<Hasher, SinglePassRange> hash(const SinglePassRange &rng, StreamHash sh = StreamHash()) {
                return detail::hash<Hasher, SinglePassRange>(rng, std::move(sh));
            };
        }    // namespace pbkdf
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PBKDF_HPP
