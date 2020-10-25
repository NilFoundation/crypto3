//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_R1CS_PPZKADSNARK_POLICY_HPP
#define CRYPTO3_R1CS_PPZKADSNARK_POLICY_HPP

#include <nil/crypto3/zk/snark/proof_systems/ppzkadsnark/r1cs_ppzkadsnark/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class r1cs_ppzkadsnark {
                    using policy_type = detail::r1cs_ppzkadsnark_basic_policy<CurveType>;

                public:
                    using snark_pp = typename policy_type::snark_pp;
                    using constraint_system = typename policy_type::constraint_system;
                    using primary_input = typename policy_type::primary_input;
                    using auxiliary_input = typename policy_type::auxiliary_input;

                    using secret_key = typename policy_type::secret_key;
                    using vkT = typename policy_type::vkT;
                    using signature = typename policy_type::signature;
                    using prf_key = typename policy_type::prf_key;

                    using pub_auth_prms_type = typename policy_type::pub_auth_prms;
                    using sec_auth_key_type = typename policy_type::sec_auth_key;
                    using pub_auth_key_type = typename policy_type::pub_auth_key;
                    using auth_data_type = typename policy_type::auth_data;

                    using proving_key_type = typename policy_type::proving_key;
                    using verification_key_type = typename policy_type::verification_key;
                    using processed_verification_key_type = typename policy_type::processed_verification_key;

                    using keypair_type = typename policy_type::keypair;
                    using proof_type = typename policy_type::proof;

                    using policy_type::generator;
                    using policy_type::online_verifier;
                    using policy_type::prover;
                    using policy_type::verifier;

                    using policy_type::auth_generator;
                    using policy_type::auth_sign;
                    using policy_type::auth_verify;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_PPZKADSNARK_POLICY_HPP
