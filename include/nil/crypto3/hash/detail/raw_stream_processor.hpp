//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_HASH_RAW_STREAM_PROCESSOR_HPP
#define CRYPTO3_HASH_RAW_STREAM_PROCESSOR_HPP

#include <array>
#include <iterator>
#include <type_traits>

#include <nil/crypto3/hash/accumulators/parameters/iterator_last.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {

            /*!
             * @brief
             *
             * @tparam Hash
             * @tparam StateAccumulator
             * @tparam Params
             */
            template<typename Construction, typename StateAccumulator, typename Params>
            class raw_stream_processor {
            protected:
                typedef typename Construction::type construction_type;
                typedef StateAccumulator accumulator_type;
                typedef Params params_type;

            public:
                typedef typename params_type::digest_endian endian_type;

                template<typename InputIterator>
                inline void operator()(InputIterator b, InputIterator e) {
                    acc(b, nil::crypto3::accumulators::iterator_last = e);
                }

                template<typename ContainerT>
                inline void operator()(const ContainerT &c) {
                    acc(c);
                }

            public:
                raw_stream_processor(accumulator_type &acc) : acc(acc) {
                }

            private:
                accumulator_type &acc;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_RAW_STREAM_PROCESSOR_HPP
