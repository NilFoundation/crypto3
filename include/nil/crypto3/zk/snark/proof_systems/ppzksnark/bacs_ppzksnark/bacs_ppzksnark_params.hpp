//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for the BACS ppzkSNARK.
//---------------------------------------------------------------------------//

#ifndef BACS_PPZKSNARK_PARAMS_HPP_
#define BACS_PPZKSNARK_PARAMS_HPP_

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs/bacs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * Below are various template aliases (used for convenience).
                 */

                template<typename ppT>
                using bacs_ppzksnark_circuit = bacs_circuit<algebra::Fr<ppT>>;

                template<typename ppT>
                using bacs_ppzksnark_primary_input = bacs_primary_input<algebra::Fr<ppT>>;

                template<typename ppT>
                using bacs_ppzksnark_auxiliary_input = bacs_auxiliary_input<algebra::Fr<ppT>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // BACS_PPZKSNARK_PARAMS_HPP_
