//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HPP
#define CRYPTO3_HASH_HPP

#include <nil/crypto3/hash/hash_value.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @defgroup hash Hash Functions & Checksums
             *
             * @brief Hash functions are one-way functions, which map data of arbitrary size to a
             * fixed output length. Most of the hash functions in crypto3 are designed to be
             * cryptographically secure, which means that it is computationally infeasible to
             * create a collision (finding two inputs with the same hash) or preimages (given a
             * hash output, generating an arbitrary input with the same hash). But note that
             * not all such hash functions meet their goals, in particular @ref nil::crypto3::hash::md4 "MD4" and @ref
             * nil::crypto3::hash::md5 "MD5" are trivially broken. However they are still included due to their wide
             * adoption in various protocols.
             *
             * Using a hash function is typically split into three stages: initialization,
             * update, and finalization (often referred to as a IUF interface). The
             * initialization stage is implicit: after creating a hash function object, it is
             * ready to process data. Then update is called one or more times. Calling update
             * several times is equivalent to calling it once with all of the arguments
             * concatenated. After completing a hash computation (eg using ``final``), the
             * internal state is reset to begin hashing a new message.
             *
             * @defgroup hash_algorithms Algorithms
             * @ingroup hash
             * @brief Algorithms are meant to provide hashing interface similar to STL algorithms' one.
             */

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam StreamHash
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename Hash, typename InputIterator, typename OutputIterator>
            OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out) {
                typedef typename hash::hash_accumulator<Hash> HashAccumulator;
                typedef typename Hash::template stream_processor<HashAccumulator, std::numeric_limits<
                        typename std::iterator_traits<InputIterator>::value_type>::digits + std::numeric_limits<
                        typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type StreamHash;

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hash, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, std::move(out), StreamHash());
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam StreamHash
             * @param first
             * @param last
             * @param out
             * @param sh
             * @return
             */
            template<typename Hash,
                     typename InputIterator,
                     typename HashAccumulator = typename hash::hash_accumulator<Hash>>
            typename HashAccumulator::type &hash(InputIterator first, InputIterator last,
                                                 typename HashAccumulator::type &sh) {
                typedef typename Hash::template stream_processor<HashAccumulator, std::numeric_limits<
                        typename std::iterator_traits<InputIterator>::value_type>::digits + std::numeric_limits<
                        typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type StreamHash;

                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hash, StreamHashImpl> HashImpl;

                return HashImpl(first, last, sh);
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam InputIterator
             * @tparam StreamHash
             * @param first
             * @param last
             * @return
             */
            template<typename Hash,
                     typename InputIterator,
                     typename StreamHash = typename Hash::template stream_processor<
                             typename hash::hash_accumulator<Hash>,
                             std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                             std::numeric_limits<
                                     typename std::iterator_traits<InputIterator>::value_type>::is_signed>::type>
            detail::range_hash_impl<Hash, detail::value_hash_impl<StreamHash>> hash(InputIterator first,
                                                                                    InputIterator last) {
                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hash, StreamHashImpl> HashImpl;

                return HashImpl(first, last, StreamHash());
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam StreamHash
             * @param rng
             * @param out
             * @return
             */
            template<typename Hash, typename SinglePassRange, typename OutputIterator>
            OutputIterator hash(const SinglePassRange &rng, OutputIterator out) {
                typedef typename hash::hash_accumulator<Hash> HashAccumulator;
                typedef typename Hash::template stream_processor<HashAccumulator, std::numeric_limits<
                        typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                                                                                  std::numeric_limits<
                                                                                          typename std::iterator_traits<
                                                                                                  typename SinglePassRange::iterator>::value_type>::is_signed>::type StreamHash;

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hash, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), StreamHash());
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam StreamHash
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Hash,
                     typename SinglePassRange,
                     typename HashAccumulator = typename hash::hash_accumulator<Hash>>
            typename HashAccumulator::type &hash(const SinglePassRange &rng, typename HashAccumulator::type &sh) {
                typedef typename Hash::template stream_processor<HashAccumulator, std::numeric_limits<
                        typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                                                                                  std::numeric_limits<
                                                                                          typename std::iterator_traits<
                                                                                                  typename SinglePassRange::iterator>::value_type>::is_signed>::type StreamHash;

                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hash, StreamHashImpl> HashImpl;

                return HashImpl(rng, sh);
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam SinglePassRange
             * @tparam StreamHash
             * @param r
             * @return
             */
            template<typename Hash,
                     typename SinglePassRange,
                     typename StreamHash = typename Hash::template stream_processor<
                             typename hash::hash_accumulator<Hash>, std::numeric_limits<typename std::iterator_traits<
                                     typename SinglePassRange::type>::value_type>::digits + std::numeric_limits<
                                     typename std::iterator_traits<
                                             typename SinglePassRange::type>::value_type>::is_signed>::type>
            detail::range_hash_impl<Hash, detail::value_hash_impl<StreamHash>> hash(const SinglePassRange &r) {

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hash, StreamHashImpl> HashImpl;

                return HashImpl(r, StreamHash());
            }
        }
    }
}

#endif //CRYPTO3_HASH_HPP
