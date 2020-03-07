//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Nil Foundation AG
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PASSHASH_GENERATE_HPP
#define CRYPTO3_PASSHASH_GENERATE_HPP

#include <nil/crypto3/passhash/algorithm/passhash.hpp>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam Passhash
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename Hasher,
                     typename InputIterator,
                     typename OutputIterator,
                     typename Passhash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            OutputIterator generate(InputIterator first, InputIterator last, OutputIterator out) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, std::move(out), Passhash());
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam OutputIterator
             * @tparam Passhash
             * @param first
             * @param last
             * @param out
             * @param sh
             * @return
             */
            template<typename Hasher,
                     typename InputIterator,
                     typename OutputIterator,
                     typename Passhash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            OutputIterator generate(InputIterator first, InputIterator last, Passhash &sh) {

                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, sh);
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam Passhash
             * @param first
             * @param last
             * @return
             */
            template<typename Hasher,
                     typename InputIterator,
                     typename Passhash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            detail::range_hash_impl<Hasher, detail::value_hash_impl<Passhash>> generate(InputIterator first,
                                                                                        InputIterator last) {
                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(first, last, Passhash());
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam Passhash
             * @param first
             * @param last
             * @param sh
             * @return
             */
            template<typename Hasher,
                     typename InputIterator,
                     typename Passhash = typename itr_stream_hash_traits<Hasher, InputIterator>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            detail::range_hash_impl<Hasher, detail::ref_hash_impl<Passhash>>
                generate(InputIterator first, InputIterator last, Passhash &sh) {
                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(first, last, sh);
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam Passhash
             * @param rng
             * @param out
             * @return
             */
            template<typename Hasher,
                     typename SinglePassRange,
                     typename OutputIterator,
                     typename Passhash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            OutputIterator generate(const SinglePassRange &rng, OutputIterator out) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), Passhash());
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam OutputIterator
             * @tparam Passhash
             * @param rng
             * @param out
             * @param sh
             * @return
             */
            template<typename Hasher,
                     typename SinglePassRange,
                     typename OutputIterator,
                     typename Passhash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            OutputIterator generate(const SinglePassRange &rng, OutputIterator out, Passhash &sh) {

                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), sh);
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam Passhash
             * @param r
             * @return
             */
            template<typename Hasher,
                     typename SinglePassRange,
                     typename Passhash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            detail::range_hash_impl<Hasher, detail::value_hash_impl<Passhash>> generate(const SinglePassRange &r) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(r, Passhash());
            }

            /*!
             * @brief
             *
             * @addtogroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam SinglePassRange
             * @tparam Passhash
             * @param rng
             * @param sh
             * @return
             */
            template<typename Hasher,
                     typename SinglePassRange,
                     typename Passhash = typename range_stream_hash_traits<Hasher, SinglePassRange>::type,
                     typename = typename std::enable_if<detail::is_stream_hash<Passhash>::value>::type>
            detail::range_hash_impl<Hasher, detail::ref_hash_impl<Passhash>> generate(const SinglePassRange &rng,
                                                                                      Passhash &sh) {
                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(rng, sh);
            }
        }    // namespace passhash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HPP
