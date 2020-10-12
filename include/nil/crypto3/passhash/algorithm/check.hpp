//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_PASSHASH_CHECK_HPP
#define CRYPTO3_PASSHASH_CHECK_HPP

#include <nil/crypto3/passhash/algorithm/passhash.hpp>

#include <nil/crypto3/passhash/passhash_value.hpp>
#include <nil/crypto3/passhash/passhash_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace passhash {
            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             *
             * @return
             */
            template<typename Hasher, typename InputIterator, typename OutputIterator>
            OutputIterator check(InputIterator first, InputIterator last, OutputIterator out) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, std::move(out), Passhash());
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
             *
             * @tparam Hasher
             * @tparam InputIterator
             * @tparam OutputIterator
             *
             * @param first
             * @param last
             * @param out
             * @param sh
             *
             * @return
             */
            template<typename Hasher, typename InputIterator, typename PasshashAccumulator =
                passhash::accumulator_set<Hashes>>
            OutputIterator check(InputIterator first, InputIterator last, PasshashAccumulator &sh) {

                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(first, last, sh);
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
            detail::range_hash_impl<Hasher, detail::value_hash_impl<Passhash>> check(InputIterator first,
                                                                                     InputIterator last) {
                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(first, last, Passhash());
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
                check(InputIterator first, InputIterator last, Passhash &sh) {
                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(first, last, sh);
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
            OutputIterator check(const SinglePassRange &rng, OutputIterator out) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), Passhash());
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
            OutputIterator check(const SinglePassRange &rng, OutputIterator out, Passhash &sh) {

                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::itr_hash_impl<Hasher, PasshashImpl, OutputIterator> HashImpl;

                return HashImpl(rng, std::move(out), sh);
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
            detail::range_hash_impl<Hasher, detail::value_hash_impl<Passhash>> check(const SinglePassRange &r) {

                typedef detail::value_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(r, Passhash());
            }

            /*!
             * @brief
             *
             * @ingroup passhash_algorithms
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
            detail::range_hash_impl<Hasher, detail::ref_hash_impl<Passhash>> check(const SinglePassRange &rng,
                                                                                   Passhash &sh) {
                typedef detail::ref_hash_impl<Passhash> PasshashImpl;
                typedef detail::range_hash_impl<Hasher, PasshashImpl> HashImpl;

                return HashImpl(rng, sh);
            }
        }    // namespace passhash
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_HPP
