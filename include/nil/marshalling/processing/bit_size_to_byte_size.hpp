//---------------------------------------------------------------------------//
// Copyright (c) 2017-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef MARSHALLING_PROCESSING_BIT_SIZE_TO_BYTE_SIZE_HPP
#define MARSHALLING_PROCESSING_BIT_SIZE_TO_BYTE_SIZE_HPP

#include <cstdint>

namespace nil {
    namespace marshalling {
        namespace processing {

            /// @cond SKIP_DOC
            template<std::size_t TSize>
            struct bit_size_to_byte_size {
                static_assert(0 < TSize, "The number of bits must be greater than 0");
                static_assert(TSize < 64, "The number of bits is too high.");
                static const std::size_t value = bit_size_to_byte_size<TSize + 1>::value;
            };

            template<>
            struct bit_size_to_byte_size<8> {
                static const std::size_t value = sizeof(std::uint8_t);
            };

            template<>
            struct bit_size_to_byte_size<16> {
                static const std::size_t value = sizeof(std::uint16_t);
            };

            template<>
            struct bit_size_to_byte_size<32> {
                static const std::size_t value = sizeof(std::uint32_t);
            };

            template<>
            struct bit_size_to_byte_size<64> {
                static const std::size_t value = sizeof(std::uint64_t);
            };

            /// @endcond

        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_BIT_SIZE_TO_BYTE_SIZE_HPP
