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

#ifndef MARSHALLING_BASIC_SUM_HPP
#define MARSHALLING_BASIC_SUM_HPP

#include <cstdint>

namespace nil {
    namespace marshalling {

        namespace protocol {

            namespace checksum {

                /// @brief Summary of all bytes checksum calculator.
                /// @details The checksum calculator class that sums all the bytes and
                ///     returns the result as a checksum value.
                /// @tparam TResult Type of the checksum result value.
                /// @headerfile nil/marshalling/protocol/checksum/BasicSum.h
                template<typename TResult = std::uint8_t>
                class basic_sum {
                public:
                    /// @brief Operator that is invoked to calculate the checksum value
                    /// @param[in, out] iter Input iterator,
                    /// @param[in] len Number of bytes to summarise.
                    /// @return The checksum value.
                    /// @post The iterator is advanced by number of bytes read (len).
                    template<typename TIter>
                    TResult operator()(TIter &iter, std::size_t len) const {
                        using byte_type = typename std::make_unsigned<typename std::decay<decltype(*iter)>::type>::type;

                        auto checksum = TResult(0);
                        for (auto idx = 0U; idx < len; ++idx) {
                            checksum += static_cast<TResult>(static_cast<byte_type>(*iter));
                            ++iter;
                        }
                        return checksum;
                    }
                };

            }    // namespace checksum

        }    // namespace protocol

    }    // namespace marshalling
}    // namespace nil
#endif    // MARSHALLING_BASIC_SUM_HPP
