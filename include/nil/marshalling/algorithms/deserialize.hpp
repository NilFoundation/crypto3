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

#ifndef MARSHALLING_DESERIALIZE_HPP
#define MARSHALLING_DESERIALIZE_HPP

#include <nil/marshalling/marshalling_state.hpp>
#include <nil/marshalling/accumulators/marshalling.hpp>
#include <nil/marshalling/accumulators/parameters/buffer_length.hpp>
#include <nil/marshalling/detail/type_traits.hpp>


namespace nil {
    namespace marshalling {
        /*!
         * @defgroup marshalling Marshalling
         *
         * @brief Marshalling between two or more defined types
         *
         * @defgroup marshalling_algorithms Algorithms
         * @ingroup marshalling
         * @brief Algorithms are meant to provide marshalling interface similar to STL algorithms' one.
         */

        /*!
         * @brief
         *
         * @ingroup marshalling_algorithms
         *
         * @tparam TypeToProcess
         * @tparam InputIterator
         *
         * @param first
         * @param last
         *
         * @return
         */
        template<typename TypeToProcess, typename InputIterator>
        TypeToProcess deserialize(InputIterator first, InputIterator last) {
            typedef accumulator_set<TypeToProcess> accumulator_set_type;
            typedef typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

            accumulator_set_type acc;

            acc(first, accumulators::buffer_length = std::distance(first, last));

            return boost::accumulators::extract_result<accumulator_type>(acc);
        }

        // /*!
        //  * @brief
        //  *
        //  * @ingroup marshalling_algorithms
        //  *
        //  * @tparam TypeToProcess
        //  * @tparam InputIterator
        //  * @tparam TypeToProcessAccumulator
        //  *
        //  * @param first
        //  * @param last
        //  * @param acc
        //  *
        //  * @return
        //  */
        // template<typename TypeToProcess, typename InputIterator, typename TypeToProcessAccumulator = accumulator_set<TypeToProcess>>
        // typename std::enable_if<boost::accumulators::detail::is_accumulator_set<TypeToProcessAccumulator>::value,
        //                         TypeToProcess>::type &
        //     deserialize(InputIterator first, InputIterator last, TypeToProcessAccumulator &acc) {
            
        //     typedef TypeToProcessAccumulator accumulator_set_type;
        //     typedef typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

        //     acc(first, std::distance(first, last));

        //     return boost::accumulators::extract_result<accumulator_type>(acc);
        // }

        // /*!
        //  * @brief
        //  *
        //  * @ingroup marshalling_algorithms
        //  *
        //  * @tparam TypeToProcess
        //  * @tparam SinglePassRange
        //  * @tparam TypeToProcessAccumulator
        //  *
        //  * @param rng
        //  * @param acc
        //  *
        //  * @return
        //  */
        // template<typename TypeToProcess, typename SinglePassRange, typename TypeToProcessAccumulator = accumulator_set<TypeToProcess>>
        // typename std::enable_if<boost::accumulators::detail::is_accumulator_set<TypeToProcessAccumulator>::value,
        //                         TypeToProcess>::type &
        //     deserialize(const SinglePassRange &rng, TypeToProcessAccumulator &acc) {
        //     typedef TypeToProcessAccumulator accumulator_set_type;
        //     typedef typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

        //     acc(rng.begin(), rng.size());

        //     return boost::accumulators::extract_result<accumulator_type>(acc);
        // }

        // /*!
        //  * @brief
        //  *
        //  * @ingroup marshalling_algorithms
        //  *
        //  * @tparam TypeToProcess
        //  * @tparam SinglePassRange
        //  * @tparam TypeToProcessAccumulator
        //  *
        //  * @param r
        //  *
        //  * @return
        //  */
        // template<typename TypeToProcess, typename SinglePassRange, typename TypeToProcessAccumulator = accumulator_set<TypeToProcess>>
        // TypeToProcess
        //     deserialize(const SinglePassRange &rng) {

        //     typedef accumulator_set<TypeToProcess> accumulator_set_type;
        //     typedef typename boost::mpl::front<typename accumulator_set_type::features_type>::type accumulator_type;

        //     accumulator_set_type acc;

        //     acc(rng.begin(), rng.size());

        //     return boost::accumulators::extract_result<accumulator_type>(acc);
        // }
    }    // namespace crypto3
}    // namespace nil

#endif    // MARSHALLING_DESERIALIZE_HPP
