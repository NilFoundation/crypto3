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

#ifndef CRYPTO3_MERKLE_UTILITIES_HPP
#define CRYPTO3_MERKLE_UTILITIES_HPP

#include <boost/filesystem.hpp>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <cmath>
#include <sstream>
#include <utility>

namespace nil {
    namespace crypto3 {
        namespace utilities {
            // returns next highest power of two from a given number if it is not
            // already a power of two.
            size_t next_pow2(size_t n) {
                return std::pow(2, std::ceil(std::log(n)));
            }
            // find power of 2 of a number which is power of 2
            size_t log2_pow2(size_t n) {
                return next_pow2(n);
            }
            // Row_Count calculation given the number of leafs in the tree and the branches.
            size_t get_merkle_tree_row_count(size_t leafs, size_t branches) {
                // Optimization
                if (branches == 2) {
                    return std::log2(leafs) + 1;
                } else {
                    return std::log(leafs) / std::log(branches) + 1;
                }
            }

            // Tree length calculation given the number of leafs in the tree and the branches.
            size_t get_merkle_tree_len(size_t leafs, size_t branches) {
                // Optimization
                if (branches == 2) {
                    return 2 * leafs - 1;
                }

                size_t len = leafs;
                size_t cur = leafs;
                size_t shift = log2_pow2(branches);
                if (shift == 0) {
                    return len;
                }

                while (cur > 0) {
                    cur >>= shift; // cur /= branches
                    len += cur;
                }

                return len;
            }

            // Tree length calculation given the number of leafs in the tree, the
            // rows_to_discard, and the branches.
            size_t get_merkle_tree_cache_size(size_t leafs, size_t branches, size_t rows_to_discard) {
                size_t shift = log2_pow2(branches);
                size_t len = get_merkle_tree_len(leafs, branches);
                size_t row_count = get_merkle_tree_row_count(leafs, branches);

                // 'row_count - 1' means that we start discarding rows above the base
                // layer, which is included in the current row_count.
                size_t cache_base = row_count - 1 - rows_to_discard;

                size_t cache_size = len;
                size_t cur_leafs = leafs;

                while (row_count > cache_base) {
                    cache_size -= cur_leafs;
                    cur_leafs >>= shift; // cur /= branches
                    row_count -= 1;
                }

                return cache_size;
            }

            bool is_merkle_tree_size_valid(size_t leafs, size_t branches) {
                if (branches == 0 || leafs != next_pow2(leafs) || branches != next_pow2(branches)) {
                    return false;
                }

                size_t cur = leafs;
                size_t shift = log2_pow2(branches);
                while (cur != 1) {
                    cur >>= shift; // cur /= branches
                    if (cur > leafs || cur == 0) {
                        return false;
                    }
                }

                return true;
            }

            // Given a tree of 'row_count' with the specified number of 'branches',
            // calculate the length of hashes required for the proof.
            size_t get_merkle_proof_lemma_len(size_t row_count, size_t branches) {
                return 2 + ((branches - 1) * (row_count - 1));
            }

            // This method returns the number of 'leafs' given a merkle tree
            // length of 'len', where leafs must be a power of 2, respecting the
            // number of branches.
            size_t get_merkle_tree_leafs(size_t len, size_t branches) {
                size_t leafs = 0;
                // Optimization:
                if (branches == 2) {
                    leafs = (len >> 1) + 1;
                } else {
                    size_t leafs = 1;
                    size_t cur = len;
                    size_t shift = log2_pow2(branches);
                    while (cur != 1) {
                        leafs <<= shift; // leafs *= branches
                        cur -= leafs;
                    }
                };

                return leafs;
            }
        }     // namespace utilities
    }         // namespace crypto3
}             // namespace nil

#endif    // CRYPTO3_MERKLE_UTILITIES_HPP
