//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Declaration of public-parameter selector for the R1CS ppzkADSNARK.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_PPZKADSNARK_PARAMS_HPP_
#define CRYPTO3_ZK_R1CS_PPZKADSNARK_PARAMS_HPP_

#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                class label_type {
                public:
                    unsigned char label_bytes[16];
                    label_type() {};
                };

                /**
                 * Below are various template aliases (used for convenience).
                 */

                template<typename r1cs_ppzkadsnark_ppT>
                using snark_pp = typename r1cs_ppzkadsnark_ppT::snark_pp;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_constraint_system =
                    r1cs_constraint_system<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_primary_input = r1cs_primary_input<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_auxiliary_input =
                    r1cs_auxiliary_input<algebra::Fr<snark_pp<r1cs_ppzkadsnark_ppT>>>;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_secret_key = typename r1cs_ppzkadsnark_ppT::skT;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_vkT = typename r1cs_ppzkadsnark_ppT::vkT;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_signature = typename r1cs_ppzkadsnark_ppT::sigT;

                template<typename r1cs_ppzkadsnark_ppT>
                using r1cs_ppzkadsnark_prf_key = typename r1cs_ppzkadsnark_ppT::prfKeyT;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_PPZKADSNARK_PARAMS_HPP_
