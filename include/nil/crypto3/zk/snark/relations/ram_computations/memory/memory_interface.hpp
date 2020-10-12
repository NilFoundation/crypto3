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
// @file Declaration of interfaces for a memory interface.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_INTERFACE_HPP_
#define CRYPTO3_ZK_MEMORY_INTERFACE_HPP_

#include <cstddef>
#include <map>
#include <vector>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A function from addresses to values that represents a memory's contents.
                 */
                typedef std::map<std::size_t, std::size_t> memory_contents;

                /**
                 * A memory interface is a virtual class for specifying and maintaining a memory.
                 *
                 * A memory is parameterized by two quantities:
                 * - num_addresses (which specifies the number of addresses); and
                 * - value_size (which specifies the number of bits stored at each address).
                 *
                 * The methods get_val and set_val can be used to load and store values.
                 */
                class memory_interface {
                public:
                    std::size_t num_addresses;
                    std::size_t value_size;

                    memory_interface(const std::size_t num_addresses, const std::size_t value_size) :
                        num_addresses(num_addresses), value_size(value_size) {
                    }
                    memory_interface(const std::size_t num_addresses, const std::size_t value_size,
                                     const std::vector<std::size_t> &contents_as_vector);
                    memory_interface(const std::size_t num_addresses, const std::size_t value_size,
                                     const memory_contents &contents);

                    virtual std::size_t get_value(std::size_t address) const = 0;
                    virtual void set_value(std::size_t address, std::size_t value) = 0;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MEMORY_INTERFACE_HPP_
