//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Parameters for *multi-predicate* ppzkPCD for R1CS.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_R1CS_MP_PPZKPCD_PARAMS_HPP_
#define CRYPTO3_ZK_R1CS_MP_PPZKPCD_PARAMS_HPP_

#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>
#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/r1cs_pcd_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_compliance_predicate =
                    r1cs_pcd_compliance_predicate<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_message = r1cs_pcd_message<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_local_data = r1cs_pcd_local_data<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_primary_input =
                    r1cs_pcd_compliance_predicate_primary_input<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_auxiliary_input =
                    r1cs_pcd_compliance_predicate_auxiliary_input<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // R1CS_MP_PPZKPCD_PARAMS_HPP_
