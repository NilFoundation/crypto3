//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Template aliasing for prettifying R1CS PCD interfaces.
//---------------------------------------------------------------------------//

#ifndef PPZKPCD_COMPLIANCE_PREDICATE_HPP_
#define PPZKPCD_COMPLIANCE_PREDICATE_HPP_

#include <nil/crypto3/zk/snark/proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /* template aliasing for R1CS (multi-predicate) ppzkPCD: */

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_compliance_predicate =
                    r1cs_pcd_compliance_predicate<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_message = r1cs_pcd_message<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_local_data = r1cs_pcd_local_data<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

                template<typename PCD_ppT>
                using r1cs_mp_ppzkpcd_variable_assignment =
                    r1cs_variable_assignment<algebra::Fr<typename PCD_ppT::curve_A_pp>>;

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PPZKPCD_COMPLIANCE_PREDICATE_HPP_
