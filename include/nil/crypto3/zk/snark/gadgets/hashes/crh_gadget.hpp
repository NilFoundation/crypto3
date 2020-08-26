//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRH_GADGET_HPP_
#define CRH_GADGET_HPP_

#include <nil/crypto3/zk/snark/gadgets/hashes/knapsack/knapsack_gadget.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                // for now all CRH gadgets are knapsack CRH's; can be easily extended
                // later to more expressive selector types.
                template<typename FieldType>
                using CRH_with_field_out_gadget = knapsack_CRH_with_field_out_gadget<FieldType>;

                template<typename FieldType>
                using CRH_with_bit_out_gadget = knapsack_CRH_with_bit_out_gadget<FieldType>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRH_GADGET_HPP_
