//---------------------------------------------------------------------------//
// Copyright (c) 2024 Iosif (x-mass) <x-mass@nil.foundation>
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

namespace nil {
    namespace crypto3 {
        namespace hashes {

            /*!
             * @brief This will feed either block or words to StateAccumulator.
             *
             * @tparam StateAccumulator
             */
            template<typename StateAccumulator>
            class raw_stream_processor {
            public:
                // Process a single value
                template<typename ValueType>
                inline void update_one(ValueType value) {
                    // Directly feed the value to acc
                    acc_(value);
                }

                // Process multiple values given by an iterator range
                template<typename InputIterator>
                inline void operator()(InputIterator first, InputIterator last) {
                    while (first != last) {
                        update_one(*first++);
                    }
                }

                // Process elements from a container
                template<typename ContainerT>
                inline void operator()(const ContainerT& container) {
                    for (const auto& value : container) {
                        update_one(value); // Use the single-value operator for consistency
                    }
                }

            public:
                raw_stream_processor(StateAccumulator &acc) : acc_(acc) {
                }

            private:
                StateAccumulator &acc_;
            };
        }    // namespace hashes
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_RAW_STREAM_PROCESSOR_HPP
