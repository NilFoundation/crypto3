//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for the memory load&store gadget.
//
// The gadget can be used to verify a memory load, followed by a store to the
// same address, from a "delegated memory".
//---------------------------------------------------------------------------//

#ifndef MEMORY_LOAD_STORE_GADGET_HPP_
#define MEMORY_LOAD_STORE_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType, typename HashT>
                using memory_load_store_gadget = merkle_tree_check_update_gadget<FieldType, HashT>;

            }
        }    // namespace zk
    }        // namespace crypto3
}    // namespace nil

#endif    // MEMORY_LOAD_STORE_GADGET_HPP_
