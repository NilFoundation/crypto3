//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP
#define CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Sample memory contents consisting of two blocks of random values;
                 * the first block is located at the beginning of memory, while
                 * the second block is located half-way through memory.
                 */
                memory_contents block_memory_contents(const std::size_t num_addresses,
                                                      const std::size_t value_size,
                                                      const std::size_t block1_size,
                                                      const std::size_t block2_size);

                /**
                 * Sample memory contents having a given number of non-zero entries;
                 * each non-zero entry is a random value at a random address (approximately).
                 */
                memory_contents random_memory_contents(const std::size_t num_addresses,
                                                       const std::size_t value_size,
                                                       const std::size_t num_filled);

                memory_contents block_memory_contents(const std::size_t num_addresses,
                                                      const std::size_t value_size,
                                                      const std::size_t block1_size,
                                                      const std::size_t block2_size) {
                    const std::size_t max_unit = 1ul << value_size;

                    memory_contents result;
                    for (std::size_t i = 0; i < block1_size; ++i) {
                        result[i] = std::rand() % max_unit;
                    }

                    for (std::size_t i = 0; i < block2_size; ++i) {
                        result[num_addresses / 2 + i] = std::rand() % max_unit;
                    }

                    return result;
                }

                memory_contents random_memory_contents(const std::size_t num_addresses,
                                                       const std::size_t value_size,
                                                       const std::size_t num_filled) {
                    const std::size_t max_unit = 1ul << value_size;

                    std::set<std::size_t> unfilled;
                    for (std::size_t i = 0; i < num_addresses; ++i) {
                        unfilled.insert(i);
                    }

                    memory_contents result;
                    for (std::size_t i = 0; i < num_filled; ++i) {
                        auto it = unfilled.begin();
                        std::advance(it, std::rand() % unfilled.size());
                        result[*it] = std::rand() % max_unit;
                        unfilled.erase(it);
                    }

                    return result;
                }

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MEMORY_CONTENTS_EXAMPLES_HPP
