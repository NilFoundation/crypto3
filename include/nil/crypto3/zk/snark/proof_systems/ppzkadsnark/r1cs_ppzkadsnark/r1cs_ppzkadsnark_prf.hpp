//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Generic PRF interface for ADSNARK.
//---------------------------------------------------------------------------//

#ifndef PRF_HPP_
#define PRF_HPP_

#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename ppT>
                r1cs_ppzkadsnark_prfKeyT<ppT> prfGen();

                template<typename ppT>
                algebra::Fr<snark_pp<ppT>> prfCompute(const r1cs_ppzkadsnark_prfKeyT<ppT> &key, const labelT &label);

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PRF_HPP_
