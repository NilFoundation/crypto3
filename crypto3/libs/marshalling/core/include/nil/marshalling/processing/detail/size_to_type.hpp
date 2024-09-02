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

#ifndef MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP
#define MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP

#include <array>
#include <cstdint>

namespace nil {
    namespace marshalling {
        namespace processing {
            namespace detail {

                template<std::size_t TSize>
                struct size_to_type_helper {
                    using type = std::array<std::uint8_t, TSize>;
                };

                template<>
                struct size_to_type_helper<1> {
                    using type = std::uint8_t;
                };

                template<>
                struct size_to_type_helper<2> {
                    using type = std::uint16_t;
                };

                template<>
                struct size_to_type_helper<4> {
                    using type = std::uint32_t;
                };

                template<>
                struct size_to_type_helper<8> {
                    using type = std::uint64_t;
                };

                template<>
                struct size_to_type_helper<3> {
                    using type = size_to_type_helper<4>::type;
                };

                template<>
                struct size_to_type_helper<5> {
                    using type = size_to_type_helper<8>::type;
                };

                template<>
                struct size_to_type_helper<6> {
                    using type = size_to_type_helper<8>::type;
                };

                template<>
                struct size_to_type_helper<7> {
                    using type = size_to_type_helper<8>::type;
                };

            }    // namespace detail
        }    // namespace processing
    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_PROCESSING_SIZE_TO_TYPE_DETAIL_HPP
