//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for the TBCS ppzkSNARK.
//---------------------------------------------------------------------------//

#ifndef TBCS_PPZKSNARK_PARAMS_HPP_
#define TBCS_PPZKSNARK_PARAMS_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs/tbcs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Below are various typedefs aliases (used for uniformity with other proof systems).
                 */

                typedef tbcs_circuit tbcs_ppzksnark_circuit;

                typedef tbcs_primary_input tbcs_ppzksnark_primary_input;

                typedef tbcs_auxiliary_input tbcs_ppzksnark_auxiliary_input;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // TBCS_PPZKSNARK_PARAMS_HPP_
