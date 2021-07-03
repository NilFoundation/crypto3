//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ZK_SNARK_ALGORITHMS_VERIFY_HPP
#define CRYPTO3_ZK_SNARK_ALGORITHMS_VERIFY_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template<typename ProofSystemType>
                bool verify(const typename ProofSystemType::verification_key_type &vk,
                            const typename ProofSystemType::primary_input_type &primary_input,
                            const typename ProofSystemType::proof_type &proof) {

                    return ProofSystemType::verify(vk, primary_input, proof);
                }

                template<typename ProofSystemType>
                bool verify(const typename ProofSystemType::processed_verification_key_type &pvk,
                            const typename ProofSystemType::primary_input_type &primary_input,
                            const typename ProofSystemType::proof_type &proof) {

                    return ProofSystemType::verify(pvk, primary_input, proof);
                }

                template<typename ProofSystemType,
                         typename DistributionType,
                         typename GeneratorType,
                         typename Hash,
                         typename InputPrimaryInputRange,
                         typename InputIterator>
                bool verify(const typename ProofSystemType::verification_srs_type &ip_verifier_srs,
                            const typename ProofSystemType::verification_key_type &pvk,
                            const InputPrimaryInputRange &public_inputs,
                            const typename ProofSystemType::aggregate_proof_type &proof,
                            InputIterator transcript_include_first,
                            InputIterator transcript_include_last) {

                    return ProofSystemType::template verify<DistributionType, GeneratorType, Hash>(
                        ip_verifier_srs, pvk, public_inputs, proof, transcript_include_first, transcript_include_last);
                }
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_SNARK_ALGORITHMS_HPP
