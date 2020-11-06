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
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/bacs_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/bacs_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/policies/bacs_ppzksnark/verifier.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FunctionsPolicy>
                class r1cs_ppzksnark {
                    using policy_type = FunctionsPolicy;

                public:
                    using constraint_system_type = typename policy_type::constraint_system;
                    using primary_input_type = typename policy_type::primary_input;
                    using auxiliary_input_type = typename policy_type::auxiliary_input;

                    using proving_key_type = typename policy_type::proving_key;
                    using verification_key_type = typename policy_type::verification_key;
                    using processed_verification_key_type = typename policy_type::processed_verification_key;

                    using keypair_type = typename policy_type::keypair;
                    using proof_type = typename policy_type::proof;

                    static inline keypair_type generator(const constraint_system_type &constraint_system) {
                        return policy_type::generator(constraint_system);
                    }

                    static inline proof_type prover(const proving_key_type &pk,
                                                    const primary_input_type &primary_input,
                                                    const auxiliary_input_type &auxiliary_input) {

                        return policy_type::prover(pk, primary_input, auxiliary_input);
                    }

                    static inline processed_verification_key_type verifier_process_vk(const verification_key_type &vk) {
                        return policy_type::verifier_process_vk(vk);
                    }

                    static inline bool online_verifier_strong_IC(const processed_verification_key_type &pvk,
                                                                 const primary_input_type &primary_input,
                                                                 const proof_type &proof) {
                        return policy_type::online_verifier_strong_IC(pvk, primary_input, proof);
                    }

                    static inline bool online_verifier_weak_IC(const processed_verification_key_type &pvk,
                                                               const primary_input_type &primary_input,
                                                               const proof_type &proof) {
                        return policy_type::online_verifier_weak_IC(pvk, primary_input, proof);
                    }

                    static inline bool verifier_strong_IC(const processed_verification_key_type &pvk,
                                                          const primary_input_type &primary_input,
                                                          const proof_type &proof) {
                        return policy_type::verifier_strong_IC(pvk, primary_input, proof);
                    }

                    static inline bool verifier_weak_IC(const processed_verification_key_type &pvk,
                                                        const primary_input_type &primary_input,
                                                        const proof_type &proof) {
                        return policy_type::verifier_weak_IC(pvk, primary_input, proof);
                    }

                    static inline bool affine_verifier_weak_IC(const processed_verification_key_type &pvk,
                                                               const primary_input_type &primary_input,
                                                               const proof_type &proof) {
                        return policy_type::verifier_weak_IC(pvk, primary_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_HPP
