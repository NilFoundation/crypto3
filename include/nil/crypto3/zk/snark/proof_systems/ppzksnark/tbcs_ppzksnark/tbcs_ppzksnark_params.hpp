//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for the TBCS ppzkSNARK.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_PARAMS_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_PARAMS_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Below are various typedefs aliases (used for uniformity with other proof systems).
                 */

                using tbcs_ppzksnark_circuit = tbcs_circuit;

                using tbcs_ppzksnark_primary_input = tbcs_primary_input;

                using tbcs_ppzksnark_auxiliary_input = tbcs_auxiliary_input;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_PARAMS_HPP
