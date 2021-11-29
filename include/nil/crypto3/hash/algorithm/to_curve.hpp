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

#ifndef CRYPTO3_HASH_TO_CURVE_HPP
#define CRYPTO3_HASH_TO_CURVE_HPP

#include <nil/crypto3/hash/to_curve_state.hpp>
#include <nil/crypto3/hash/to_curve_value.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

namespace nil {
    namespace crypto3 {
        /*!
         * @defgroup hash_algorithms Algorithms
         * @ingroup hashes
         * @brief Algorithms are meant to provide hashing to curve interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam OutputIterator
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
            to_curve(InputIterator first, InputIterator last, OutputIterator out) {
            typedef hashing_to_curve_accumulator_set<Hash> HashingAccumulator;

            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_to_curve_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(first, last, std::move(out), HashingAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashingAccumulator
         *
         * @param first
         * @param last
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename InputIterator,
                 typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashingAccumulator>::value,
                                HashingAccumulator>::type &
            to_curve(InputIterator first, InputIterator last, HashingAccumulator &sh) {
            typedef hashes::detail::ref_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, std::forward<HashingAccumulator>(sh));
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam InputIterator
         * @tparam HashingAccumulator
         *
         * @param first
         * @param last
         *
         * @return
         */
        template<typename Hash, typename InputIterator,
                 typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        hashes::detail::range_to_curve_impl<hashes::detail::value_to_curve_impl<typename std::enable_if<
            boost::accumulators::detail::is_accumulator_set<HashingAccumulator>::value, HashingAccumulator>::type>>
            to_curve(InputIterator first, InputIterator last) {
            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(first, last, HashingAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange, typename OutputIterator>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            to_curve(const SinglePassRange &rng, OutputIterator out) {
            typedef hashing_to_curve_accumulator_set<Hash> HashingAccumulator;

            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_to_curve_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(rng, std::move(out), HashingAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashingAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange,
                 typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashingAccumulator>::value,
                                HashingAccumulator>::type &
            to_curve(const SinglePassRange &rng, HashingAccumulator &sh) {
            typedef hashes::detail::ref_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, std::forward<HashingAccumulator>(sh));
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam SinglePassRange
         * @tparam HashingAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename Hash, typename SinglePassRange,
                 typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        hashes::detail::range_to_curve_impl<hashes::detail::value_to_curve_impl<HashingAccumulator>>
            to_curve(const SinglePassRange &r) {

            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashingAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam OutputIterator
         *
         * @param rng
         * @param out
         *
         * @return
         */
        template<typename Hash, typename T, typename OutputIterator>
        typename std::enable_if<::nil::crypto3::detail::is_iterator<OutputIterator>::value, OutputIterator>::type
            to_curve(std::initializer_list<T> list, OutputIterator out) {
            typedef hashing_to_curve_accumulator_set<Hash> HashingAccumulator;

            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::itr_to_curve_impl<StreamHashImpl, OutputIterator> HashImpl;

            return HashImpl(list, std::move(out), HashingAccumulator());
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashingAccumulator
         *
         * @param rng
         * @param sh
         *
         * @return
         */
        template<typename Hash, typename T, typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        typename std::enable_if<boost::accumulators::detail::is_accumulator_set<HashingAccumulator>::value,
                                HashingAccumulator>::type &
            to_curve(std::initializer_list<T> rng, HashingAccumulator &sh) {
            typedef hashes::detail::ref_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(rng, std::forward<HashingAccumulator>(sh));
        }

        /*!
         * @brief
         *
         * @ingroup hash_algorithms
         *
         * @tparam Hash
         * @tparam T
         * @tparam HashingAccumulator
         *
         * @param r
         *
         * @return
         */
        template<typename Hash, typename T, typename HashingAccumulator = hashing_to_curve_accumulator_set<Hash>>
        hashes::detail::range_to_curve_impl<hashes::detail::value_to_curve_impl<HashingAccumulator>>
            to_curve(std::initializer_list<T> r) {

            typedef hashes::detail::value_to_curve_impl<HashingAccumulator> StreamHashImpl;
            typedef hashes::detail::range_to_curve_impl<StreamHashImpl> HashImpl;

            return HashImpl(r, HashingAccumulator());
        }
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_TO_CURVE_HPP
