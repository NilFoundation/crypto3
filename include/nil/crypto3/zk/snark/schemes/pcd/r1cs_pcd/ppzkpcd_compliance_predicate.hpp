//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Template aliasing for prettifying R1CS PCD interfaces.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PPZKPCD_COMPLIANCE_PREDICATE_HPP
#define CRYPTO3_ZK_PPZKPCD_COMPLIANCE_PREDICATE_HPP

#include <nil/crypto3/zk/snark/schemes/pcd/r1cs_pcd/compliance_predicate.hpp>

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

#endif    // PPZKPCD_COMPLIANCE_PREDICATE_HPP
