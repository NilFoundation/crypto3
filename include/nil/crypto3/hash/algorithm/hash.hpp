//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_HPP
#define CRYPTO3_HASH_HPP

#include <nil/crypto3/hash/hash_value.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

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
            typename std::enable_if<!boost::accumulators::detail::is_accumulator_set<OutputIterator>::value,
                                    OutputIterator>::type
                hash(InputIterator first, InputIterator last, OutputIterator out) {
                typedef typename hash::hash_accumulator_set<Hash> HashAccumulator;

                typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, std::move(out), HashAccumulator());
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
            template<typename Hash, typename InputIterator,
                     typename HashAccumulator = typename hash::hash_accumulator_set<Hash>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
                                    HashAccumulator>::type &
                hash(InputIterator first, InputIterator last, HashAccumulator &sh) {
                typedef detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                return HashImpl(first, last, std::forward<HashAccumulator>(sh));
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
            template<typename Hash, typename InputIterator, typename HashAccumulator = hash::hash_accumulator_set<Hash>>
            detail::range_hash_impl<detail::value_hash_impl<typename std::enable_if<
                boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value, HashAccumulator>::type>>
                hash(InputIterator first, InputIterator last) {
                typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                return HashImpl(first, last, HashAccumulator());
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
            typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
                hash(const SinglePassRange &rng, OutputIterator out) {
                typedef typename hash::hash_accumulator_set<Hash> HashAccumulator;

                typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::itr_hash_impl<StreamHashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), HashAccumulator());
            }

            /*!
             * @brief
             *
             * @ingroup hash_algorithms
             *
             * @tparam Hash
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam HashAccumulator
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Hash, typename SinglePassRange,
                     typename HashAccumulator = typename hash::hash_accumulator_set<Hash>>
            typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashAccumulator>::value,
                                    HashAccumulator>::type &
                hash(const SinglePassRange &rng, HashAccumulator &sh) {
                typedef detail::ref_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                return HashImpl(rng, std::forward<HashAccumulator>(sh));
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
            template<typename Hash, typename SinglePassRange,
                     typename HashAccumulator = hash::hash_accumulator_set<Hash>>
            detail::range_hash_impl<detail::value_hash_impl<HashAccumulator>> hash(const SinglePassRange &r) {

                typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                return HashImpl(r, HashAccumulator());
            }
        }    // namespace hash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HPP