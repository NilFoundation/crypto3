//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
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

#ifndef CRYPTO3_MERKLE_TREE_NODE_HPP
#define CRYPTO3_MERKLE_TREE_NODE_HPP

namespace nil {
    namespace crypto3 {
        namespace containers {
            namespace detail {
                template<typename Hash>
                struct merkle_tree_node {
                    typedef Hash hash_type;

                    constexpr static const std::size_t digest_bits = hash_type::digest_bits;
                    typedef typename hash_type::digest_type digest_type;

                    typedef typename Hash::digest_type value_type;
                    constexpr static const std::size_t value_bits = digest_bits;
                };
            }    // namespace detail
        }        // namespace containers
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_NODE_HPP
