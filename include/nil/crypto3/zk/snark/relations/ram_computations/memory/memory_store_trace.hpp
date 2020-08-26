//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for a memory store trace.
//---------------------------------------------------------------------------//

#ifndef MEMORY_STORE_TRACE_HPP_
#define MEMORY_STORE_TRACE_HPP_

#include <nil/crypto3/zk/snark/relations/ram_computations/memory/memory_interface.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A pair consisting of an address and a value.
                 * It represents a memory store.
                 */
                typedef std::pair<std::size_t, std::size_t> address_and_value;

                /**
                 * A list in which each component consists of a timestamp and a memory store.
                 */
                class memory_store_trace {
                private:
                    std::map<std::size_t, address_and_value> entries;

                public:
                    memory_store_trace();
                    address_and_value get_trace_entry(std::size_t timestamp) const;
                    std::map<std::size_t, address_and_value> get_all_trace_entries() const;
                    void set_trace_entry(std::size_t timestamp, const address_and_value &av);

                    memory_contents as_memory_contents() const;
                };

                memory_store_trace::memory_store_trace() {
                }

                address_and_value memory_store_trace::get_trace_entry(std::size_t timestamp) const {
                    auto it = entries.find(timestamp);
                    return (it != entries.end() ? it->second : std::make_pair<std::size_t, std::size_t>(0, 0));
                }

                std::map<std::size_t, address_and_value> memory_store_trace::get_all_trace_entries() const {
                    return entries;
                }

                void memory_store_trace::set_trace_entry(std::size_t timestamp, const address_and_value &av) {
                    entries[timestamp] = av;
                }

                memory_contents memory_store_trace::as_memory_contents() const {
                    memory_contents result;

                    for (auto &ts_and_addrval : entries) {
                        result[ts_and_addrval.second.first] = ts_and_addrval.second.second;
                    }

                    return result;
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // MEMORY_STORE_TRACE_HPP_
