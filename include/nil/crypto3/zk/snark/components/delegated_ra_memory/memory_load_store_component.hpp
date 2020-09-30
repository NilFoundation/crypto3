//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the memory load&store component.
//
// The component can be used to verify a memory load, followed by a store to the
// same address, from a "delegated memory".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP
#define CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP

#include <nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_update_components.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                using memory_load_store_component = merkle_tree_check_update_component<FieldType, Hash>;

            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_MEMORY_LOAD_STORE_COMPONENT_HPP
