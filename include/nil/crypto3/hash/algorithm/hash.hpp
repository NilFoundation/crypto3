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

#include <nil/crypto3/hash/detail/stream_postprocessor.hpp>

namespace nil {
    namespace crypto3 {
        namespace hash {
            /*!
             * @defgroup hash_algorithms Algorithms
             * @ingroup hash
             * @brief Algorithms are meant to provide hashing interface similar to STL algorithms' one.
             */

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
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
            template<typename Hasher, typename InputIterator, typename OutputIterator,
                     typename StreamHash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(InputIterator first, InputIterator last, OutputIterator out) {

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hasher, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, std::move(out), StreamHash());
            }

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
                     typename StreamHash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(InputIterator first, InputIterator last, StreamHash &sh) {

                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hasher, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, sh);
            }

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
             * @return
             */
            template<typename Hasher, typename InputIterator,
                     typename StreamHash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::range_hash_impl<Hasher, detail::value_hash_impl<StreamHash>> hash(InputIterator first,
                                                                                      InputIterator last) {
                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hasher, StreamHashImpl> HashImpl;

                return HashImpl(first, last, StreamHash());
            }

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
                     typename StreamHash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::range_hash_impl<Hasher, detail::ref_hash_impl<StreamHash>> hash(InputIterator first,
                                                                                    InputIterator last,
                                                                                    StreamHash &sh) {
                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hasher, StreamHashImpl> HashImpl;

                return HashImpl(first, last, sh);

            }

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
             * @return
             */
            template<typename Hasher, typename SinglePassRange, typename OutputIterator,
                     typename StreamHash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(const SinglePassRange &rng, OutputIterator out) {

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hasher, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), StreamHash());
            }

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
                     typename StreamHash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            OutputIterator hash(const SinglePassRange &rng, OutputIterator out, StreamHash &sh) {

                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::itr_hash_impl<Hasher, StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), sh);
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam StreamHash
             * @param r
             * @return
             */
            template<typename Hasher, typename SinglePassRange,
                     typename StreamHash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::range_hash_impl<Hasher, detail::value_hash_impl<StreamHash>> hash(const SinglePassRange &r) {

                typedef detail::value_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hasher, StreamHashImpl> HashImpl;

                return HashImpl(r, StreamHash());
            }

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
                     typename StreamHash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<StreamHash>::value>::type>
            detail::range_hash_impl<Hasher, detail::ref_hash_impl<StreamHash>> hash(const SinglePassRange &rng,
                                                                                    StreamHash &sh) {
                typedef detail::ref_hash_impl<StreamHash> StreamHashImpl;
                typedef detail::range_hash_impl<Hasher, StreamHashImpl> HashImpl;

                return HashImpl(rng, sh);
            }
        }
    }
}

#endif //CRYPTO3_HASH_HPP
