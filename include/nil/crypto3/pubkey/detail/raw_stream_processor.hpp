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

#ifndef CRYPTO3_PUBKEY_RAW_STREAM_PROCESSOR_HPP
#define CRYPTO3_PUBKEY_RAW_STREAM_PROCESSOR_HPP

#include <type_traits>
#include <iterator>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Mode, typename AccumulatorSet, typename Params>
            struct raw_stream_processor {
            private:
                typedef Mode mode_type;
                typedef AccumulatorSet accumulator_set_type;
                typedef Params params_type;

                constexpr static const auto input_block_bits = mode_type::input_block_bits;
                typedef typename mode_type::input_block_type input_block_type;

                constexpr static const auto input_value_bits = mode_type::input_value_bits;
                typedef typename mode_type::input_value_type input_value_type;

            public:
                raw_stream_processor(accumulator_set_type &s) : acc(s) {
                }

                template<typename InputIterator,
                         typename ValueType = typename std::iterator_traits<InputIterator>::value_type,
                         typename = typename std::enable_if<
                             std::is_same<input_value_type, ValueType>::value>::type>
                inline void operator()(InputIterator first, InputIterator last) {
                    input_block_type block(first, last);
                    acc(block);
                }

                inline void operator()(const input_block_type &block) {
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

#endif    // CRYPTO3_PUBKEY_RAW_STREAM_PROCESSOR_HPP
