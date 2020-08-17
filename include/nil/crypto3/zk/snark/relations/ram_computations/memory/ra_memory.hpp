//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a random-access memory.
//---------------------------------------------------------------------------//

#ifndef RA_MEMORY_HPP_
#define RA_MEMORY_HPP_

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A random-access memory maintains the memory's contents via a map (from addresses to values).
                 */
                class ra_memory : public memory_interface {
                public:
                    memory_contents contents;

                    ra_memory(const size_t num_addresses, const size_t value_size);
                    ra_memory(const size_t num_addresses, const size_t value_size,
                              const std::vector<size_t> &contents_as_vector);
                    ra_memory(const size_t num_addresses, const size_t value_size, const memory_contents &contents);

                    size_t get_value(const size_t address) const;
                    void set_value(const size_t address, const size_t value);
                };

                ra_memory::ra_memory(const size_t num_addresses, const size_t value_size) :
                    memory_interface(num_addresses, value_size) {
                }

                ra_memory::ra_memory(const size_t num_addresses,
                                     const size_t value_size,
                                     const std::vector<size_t> &contents_as_vector) :
                    memory_interface(num_addresses, value_size) {
                    /* copy std::vector into std::map */
                    for (size_t i = 0; i < contents_as_vector.size(); ++i) {
                        contents[i] = contents_as_vector[i];
                    }
                }

                ra_memory::ra_memory(const size_t num_addresses,
                                     const size_t value_size,
                                     const memory_contents &contents) :
                    memory_interface(num_addresses, value_size),
                    contents(contents) {
                }

                size_t ra_memory::get_value(const size_t address) const {
                    assert(address < num_addresses);
                    auto it = contents.find(address);
                    return (it == contents.end() ? 0 : it->second);
                }

                void ra_memory::set_value(const size_t address, const size_t value) {
                    contents[address] = value;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // RA_MEMORY_HPP_
