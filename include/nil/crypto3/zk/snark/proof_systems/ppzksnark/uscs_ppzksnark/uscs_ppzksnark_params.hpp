//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for the USCS ppzkSNARK.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_USCS_PPZKSNARK_PARAMS_HPP_
#define CRYPTO3_ZK_USCS_PPZKSNARK_PARAMS_HPP_

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/uscs/uscs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Below are various template aliases (used for convenience).
                 */

                template<typename CurveType>
                using uscs_ppzksnark_constraint_system = uscs_constraint_system<typename CurveType::scalar_field_type>;

                template<typename CurveType>
                using uscs_ppzksnark_primary_input = uscs_primary_input<typename CurveType::scalar_field_type>;

                template<typename CurveType>
                using uscs_ppzksnark_auxiliary_input = uscs_auxiliary_input<typename CurveType::scalar_field_type>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // USCS_PPZKSNARK_PARAMS_HPP_
