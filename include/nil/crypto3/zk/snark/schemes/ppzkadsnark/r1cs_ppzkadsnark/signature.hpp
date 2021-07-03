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
// @file Generic signature interface for ADSNARK.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_SIGNATURE_HPP
#define CRYPTO3_ZK_SIGNATURE_HPP

#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                struct kpT {
                    r1cs_ppzkadsnark_secret_key<CurveType> sk;
                    r1cs_ppzkadsnark_vkT<CurveType> vk;
                };

                template<typename CurveType>
                kpT<CurveType> sigGen(void);

                template<typename CurveType>
                r1cs_ppzkadsnark_signature<CurveType> sigSign(const r1cs_ppzkadsnark_secret_key<CurveType> &sk,
                                                              const label_type &label,
                                                              const typename CurveType::g2_type::value_type &Lambda);

                template<typename CurveType>
                bool sigVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const label_type &label,
                              const typename CurveType::g2_type::value_type &Lambda,
                              const r1cs_ppzkadsnark_signature<CurveType> &sig);

                template<typename CurveType>
                bool sigBatchVerif(const r1cs_ppzkadsnark_vkT<CurveType> &vk, const std::vector<label_type> &labels,
                                   const std::vector<typename CurveType::g2_type::value_type> &Lambdas,
                                   const std::vector<r1cs_ppzkadsnark_signature<CurveType>> &sigs);

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SIGNATURE_HPP
