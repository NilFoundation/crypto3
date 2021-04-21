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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_ACCUMULATE_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_ACCUMULATE_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename ProofSystemType, template<typename T> class ProofRange>
                bool aggregate(const typename ProofSystemType::processed_verification_key_type &pvk,
                               const typename ProofSystemType::primary_input_type &primary_input,
                               const typename ProofSystemType::proof_type &proof) {

                    return ProofSystemType::online_verify(pvk, primary_input, proof);
                }

                template<typename ProofSystemType>
                typename ProofSystemType::keypair_type
                    generate_keys(const typename ProofSystemType::constraint_system_type &constraint_system) {

                    return ProofSystemType::generate(constraint_system);
                }

                template<typename ProofSystemType>
                typename ProofSystemType::proof_type
                    prove(const typename ProofSystemType::proving_key_type &pk,
                          const typename ProofSystemType::primary_input_type &primary_input,
                          const typename ProofSystemType::auxiliary_input_type &auxiliary_input) {

                    return ProofSystemType::prove(pk, primary_input, auxiliary_input);
                }

                template<typename ProofSystemType>
                bool verity(const typename ProofSystemType::verification_key_type &vk,
                            const typename ProofSystemType::primary_input_type &primary_input,
                            const typename ProofSystemType::proof_type &proof) {

                    return ProofSystemType::verify(vk, primary_input, proof);
                }

                template<typename ProofSystemType>
                bool online_verifier(const typename ProofSystemType::processed_verification_key_type &pvk,
                                     const typename ProofSystemType::primary_input_type &primary_input,
                                     const typename ProofSystemType::proof_type &proof) {

                    return ProofSystemType::online_verify(pvk, primary_input, proof);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_HPP
