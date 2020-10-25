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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_ppzksnark/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename CurveType>
                class r1cs_ppzksnark : private detail::r1cs_ppzksnark_basic_policy<CurveType> {
                    using policy_type = detail::r1cs_ppzksnark_basic_policy<CurveType>;

                public:
                    using constraint_system_type = typename policy_type::constraint_system;
                    using primary_input_type = typename policy_type::primary_input;
                    using auxiliary_input_type = typename policy_type::auxiliary_input;

                    using proving_key_type = typename policy_type::proving_key;
                    using verification_key_type = typename policy_type::verification_key;
                    using processed_verification_key_type = typename policy_type::processed_verification_key;

                    using keypair_type = typename policy_type::keypair;
                    using proof_type = typename policy_type::proof;

                    using policy_type::generator;
                    using policy_type::prover;

                    using policy_type::verifier_process_vk;

                    using policy_type::online_verifier_strong_IC;
                    using policy_type::online_verifier_weak_IC;
                    using policy_type::verifier_strong_IC;
                    using policy_type::verifier_weak_IC;

                    using policy_type::affine_verifier_weak_IC;
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_HPP
