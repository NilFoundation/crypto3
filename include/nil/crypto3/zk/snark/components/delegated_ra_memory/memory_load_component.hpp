//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the memory load component.
// The component can be used to verify a memory load from a "delegated memory".
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_MEMORY_LOAD_COMPONENT_HPP_
#define CRYPTO3_ZK_MEMORY_LOAD_COMPONENT_HPP_

#include <nil/crypto3/zk/snark/components/merkle_tree/merkle_tree_check_read_component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename Hash>
                using memory_load_component = merkle_tree_check_read_component<FieldType, Hash>;

            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // MEMORY_LOAD_COMPONENT_HPP_
