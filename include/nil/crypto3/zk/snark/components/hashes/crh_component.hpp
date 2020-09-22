//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_CRH_COMPONENT_HPP
#define CRYPTO3_ZK_CRH_COMPONENT_HPP

#include <nil/crypto3/zk/snark/components/hashes/knapsack/knapsack_component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                // for now all CRH components are knapsack CRH's; can be easily extended
                // later to more expressive selector types.
                template<typename FieldType>
                using crh_with_field_out_component = knapsack_crh_with_field_out_component<FieldType>;

                template<typename FieldType>
                using crh_with_bit_out_component = knapsack_crh_with_bit_out_component<FieldType>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_CRH_COMPONENT_HPP
