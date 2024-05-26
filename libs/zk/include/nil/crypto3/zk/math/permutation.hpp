//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef CRYPTO3_ZK_MATH_PLONK_PERMUTATION_HPP
#define CRYPTO3_ZK_MATH_PLONK_PERMUTATION_HPP

namespace nil {
    namespace crypto3 {
        namespace math {

            struct plonk_permutation {
                typedef std::pair<std::size_t, std::size_t> key_type;
                typedef std::pair<std::size_t, std::size_t> value_type;

                std::map<key_type, value_type> _permutation_map;

                plonk_permutation(std::size_t columns, std::size_t rows) {
                    for (std::size_t i = 0; i < columns; i++) {
                        for (std::size_t j = 0; j < rows; j++) {
                            auto key = key_type(i, j);
                            _permutation_map[key] = value_type(i, j);
                        }
                    }
                }

                plonk_permutation() {
                }

                void cells_equal(key_type cell, key_type equal_to) {
                    _permutation_map[cell] = _permutation_map[equal_to];
                }

                void cells_equal(std::size_t cell_x, std::size_t cell_y, std::size_t equal_to_x,
                                 std::size_t equal_to_y) {
                    _permutation_map[key_type(cell_x, cell_y)] = _permutation_map[key_type(equal_to_x, equal_to_y)];
                }

                value_type &operator[](key_type key) {
                    return _permutation_map[key];
                }
            };

        }    // namespace math
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MATH_PLONK_PERMUTATION_HPP