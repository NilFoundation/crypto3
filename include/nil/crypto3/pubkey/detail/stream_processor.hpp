//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Aleksey Moskvin <zerg1996@yandex.ru>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_PUBKEY_STREAM_PROCESSOR_HPP
#define CRYPTO3_PUBKEY_STREAM_PROCESSOR_HPP

#include <iterator>
#include <type_traits>
#include <algorithm>

#include <nil/crypto3/detail/pack.hpp>
#include <nil/crypto3/detail/digest.hpp>

#include <nil/crypto3/pubkey/accumulators/parameters/iterator_last.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/range/algorithm/copy.hpp>

#include <boost/mpl/vector.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Mode, typename AccumulatorSet, typename Params>
            struct stream_processor {
            private:
                typedef Mode mode_type;
                typedef AccumulatorSet accumulator_set_type;
                typedef Params params_type;

                constexpr static const auto input_block_bits = mode_type::input_block_bits;
                typedef typename mode_type::input_block_type input_block_type;

                constexpr static const auto input_value_bits = mode_type::input_value_bits;
                typedef typename mode_type::input_value_type input_value_type;

            public:
                typedef typename params_type::endian_type endian_type;

                constexpr static const std::size_t value_bits = params_type::value_bits;
                typedef typename boost::uint_t<value_bits>::least value_type;

            private:
                constexpr static const bool enable_packer = value_bits > 0;

            public:
                stream_processor(accumulator_set_type &s) : acc(s) {
                }

                template<typename InputIterator, bool ep = enable_packer,
                         typename std::enable_if<ep, bool>::type = true>
                inline void operator()(InputIterator first, InputIterator last) {
                    input_block_type block {};
                    ::nil::crypto3::detail::pack_to<endian_type, value_bits, input_value_bits>(
                        first, last, std::back_inserter(block));
                    acc(block);
                }

                template<typename InputIterator1, typename InputIterator2, bool ep = enable_packer,
                         typename std::enable_if<ep, bool>::type = true>
                inline void operator()(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                       InputIterator2 last2) {
                    input_block_type block {};
                    ::nil::crypto3::detail::pack_to<endian_type, value_bits, input_value_bits>(
                        first1, last1, std::back_inserter(block));
                    acc(block);
                    acc(first2, nil::crypto3::accumulators::iterator_last = last2);
                }

                template<typename InputIterator, bool ep = enable_packer,
                         typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                         typename std::enable_if<!ep, bool>::type = true,
                         typename mode_type::template check_input_value_type<ValueType> = true>
                inline void operator()(InputIterator first, InputIterator last) {
                    acc(first, nil::crypto3::accumulators::iterator_last = last);
                }

                // TODO: implement second input value check
                template<typename InputIterator1, typename InputIterator2, bool ep = enable_packer,
                         typename ValueType1 = typename std::iterator_traits<InputIterator1>::value_type,
                         typename ValueType2 = typename std::iterator_traits<InputIterator2>::value_type,
                         typename std::enable_if<!ep, bool>::type = true,
                         typename mode_type::template check_input_value_type<ValueType1> = true>
                inline void operator()(InputIterator1 first1, InputIterator1 last1, InputIterator2 first2,
                                       InputIterator2 last2) {
                    acc(first1, nil::crypto3::accumulators::iterator_last = last1);
                    acc(first2, nil::crypto3::accumulators::iterator_last = last2);
                }

                template<
                    typename SinglePassRange, bool ep = enable_packer,
                    typename ValueType = typename std::iterator_traits<typename SinglePassRange::iterator>::value_type,
                    typename std::enable_if<!ep, bool>::type = true,
                    typename mode_type::template check_input_value_type<ValueType> = true>
                inline void operator()(const SinglePassRange &block) {
                    acc(block);
                }

                inline void operator()(const input_value_type &value) {
                    acc(value);
                }

                template<typename ValueType>
                inline void operator()(const std::initializer_list<ValueType> &il) {
                    return operator()(il.begin(), il.end());
                }

                void reset() {
                }

                accumulator_set_type &acc;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_STREAM_PROCESSOR_HPP
