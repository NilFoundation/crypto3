//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_R1CS_PPZKADSNARK_POLICY_HPP
#define CRYPTO3_R1CS_PPZKADSNARK_POLICY_HPP

#include <nil/crypto3/zk/snark/schemes/ppzkadsnark/r1cs_ppzkadsnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class r1cs_ppzkadsnark {
                    typedef detail::r1cs_ppzkadsnark_basic_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::snark_pp snark_pp;
                    typedef typename policy_type::constraint_system_type constraint_system;
                    typedef typename policy_type::primary_input_type primary_input;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input;

                    typedef typename policy_type::secret_key secret_key;
                    typedef typename policy_type::vkT vkT;
                    typedef typename policy_type::signature signature;
                    typedef typename policy_type::prf_key prf_key;

                    typedef typename policy_type::pub_auth_prms pub_auth_prms_type;
                    typedef typename policy_type::sec_auth_key sec_auth_key_type;
                    typedef typename policy_type::pub_auth_key pub_auth_key_type;
                    typedef typename policy_type::auth_data auth_data_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof proof_type;

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
