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

#ifndef CRYPTO3_ZK_SIGNATURE_HPP
#define CRYPTO3_ZK_SIGNATURE_HPP

#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/r1cs_ppzkadsnark_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class kpT {
                public:
                    r1cs_ppzkadsnark_secret_key<CurveType> sk;
                    r1cs_ppzkadsnark_vkT<CurveType> vk;
                };

                template<typename CurveType>
                kpT<CurveType> sigGen(void);

                template<typename CurveType>
                r1cs_ppzkadsnark_signature<CurveType> sigSign(const r1cs_ppzkadsnark_secret_key<CurveType> &sk, const label_type &label,
                                                   const typename CurveType::g2_type &Lambda);

                template<typename CurveType>
                bool sigVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const label_type &label,
                              const typename CurveType::g2_type &Lambda, const r1cs_ppzkadsnark_signature<CurveType> &sig);

                template<typename CurveType>
                bool sigBatchVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const std::vector<label_type> &labels,
                                   const std::vector<typename CurveType::g2_type> &Lambdas,
                                   const std::vector<r1cs_ppzkadsnark_signature<CurveType>> &sigs);

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SIGNATURE_HPP
