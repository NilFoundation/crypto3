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

#ifndef CRYPTO3_HASH_DETAIL_PEDERSEN_BASIC_FUNCTIONS_HPP
#define CRYPTO3_HASH_DETAIL_PEDERSEN_BASIC_FUNCTIONS_HPP

#include <cstddef>

#include <nil/crypto3/detail/static_pow.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                /// See definition of \p c in https://zips.z.cash/protocol/protocol.pdf#concretepedersenhash
                template<typename Field>
                constexpr std::size_t chunks_per_base_point(std::size_t chunk_bits) {
                    typename Field::extended_integral_type two(2);
                    std::size_t c = 1;
                    std::size_t prev_c = 0;
                    /// (Fr - 1) / 2
                    typename Field::extended_integral_type upper_bound = (Field::modulus - 1) / 2;
                    // TODO: first multiplier should be verified
                    /// (chunk_bits + 1) * ((2^(c * (chunk_bits + 1)) - 1) / (2^(chunk_bits + 1) - 1))
                    auto get_test_value = [&](auto i) {
                        return (chunk_bits + 1) * ((::nil::crypto3::detail::pow(two, i * (chunk_bits + 1)) - 1) /
                                                   (::nil::crypto3::detail::pow(two, chunk_bits + 1) - 1));
                    };
                    auto test_value = get_test_value(c);

                    while (test_value <= upper_bound) {
                        prev_c = c++;
                        test_value = get_test_value(c);
                    }

                    return prev_c;
                }
            }    // namespace detail
        }        // namespace hashes
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASH_DETAIL_PEDERSEN_BASIC_FUNCTIONS_HPP
