//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//
// @file Generic signature interface for ADSNARK.
//---------------------------------------------------------------------------//

#ifndef SIGNATURE_HPP_
#define SIGNATURE_HPP_

#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class kpT {
                public:
                    r1cs_ppzkadsnark_skT<CurveType> sk;
                    r1cs_ppzkadsnark_vkT<CurveType> vk;
                };

                template<typename CurveType>
                kpT<CurveType> sigGen(void);

                template<typename CurveType>
                r1cs_ppzkadsnark_sigT<CurveType> sigSign(const r1cs_ppzkadsnark_skT<CurveType> &sk, const labelT &label,
                                                   const CurveType::g2_type &Lambda);

                template<typename CurveType>
                bool sigVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const labelT &label,
                              const CurveType::g2_type &Lambda, const r1cs_ppzkadsnark_sigT<CurveType> &sig);

                template<typename CurveType>
                bool sigBatchVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const std::vector<labelT> &labels,
                                   const std::vector<CurveType::g2_type> &Lambdas,
                                   const std::vector<r1cs_ppzkadsnark_sigT<CurveType>> &sigs);

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // SIGNATURE_HPP_
