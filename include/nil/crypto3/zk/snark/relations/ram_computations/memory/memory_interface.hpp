//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a memory interface.
//---------------------------------------------------------------------------//

#ifndef MEMORY_INTERFACE_HPP_
#define MEMORY_INTERFACE_HPP_

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
                typedef std::map<size_t, size_t> memory_contents;

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
                    size_t num_addresses;
                    size_t value_size;

                    memory_interface(const size_t num_addresses, const size_t value_size) :
                        num_addresses(num_addresses), value_size(value_size) {
                    }
                    memory_interface(const size_t num_addresses, const size_t value_size,
                                     const std::vector<size_t> &contents_as_vector);
                    memory_interface(const size_t num_addresses, const size_t value_size,
                                     const memory_contents &contents);

                    virtual size_t get_value(size_t address) const = 0;
                    virtual void set_value(size_t address, size_t value) = 0;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MEMORY_INTERFACE_HPP_
