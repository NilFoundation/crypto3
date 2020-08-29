//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

                template<typename CurveType>
                r1cs_ppzkadsnark_prfKeyT<CurveType> prfGen();

                template<typename CurveType>
                CurveType::scalar_field_type::value_type prfCompute(const r1cs_ppzkadsnark_prfKeyT<CurveType> &key, const labelT &label);

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // PRF_HPP_
