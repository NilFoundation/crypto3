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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_HPP

#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/generator.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/prover.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/bacs_ppzksnark/verifier.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                /*!
                 * @brief ppzkSNARK for BACS.
                 * @tparam CurveType
                 * @tparam Generator
                 * @tparam Prover
                 * @tparam Verifier
                 *
                 * @details The implementation is a straightforward combination of:
                 * (1) a BACS-to-R1CS reduction, and
                 * (2) a ppzkSNARK for R1CS.
                 *
                 * Acronyms:
                 * - BACS = "Bilinear Arithmetic Circuit Satisfiability"
                 * - R1CS = "Rank-1 Constraint System"
                 * - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
                 */
                template<typename CurveType,
                         typename Generator = bacs_ppzksnark_generator<CurveType>,
                         typename Prover = bacs_ppzksnark_prover<CurveType>,
                         typename Verifier = bacs_ppzksnark_verifier_strong_input_consistency<CurveType>>
                class bacs_ppzksnark {
                    typedef detail::bacs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline keypair_type generate(const circuit_type &circuit) {
                        return Generator::process(circuit);
                    }

                    static inline proof_type prove(const proving_key_type &pk,
                                                   const primary_input_type &primary_input,
                                                   const auxiliary_input_type &auxiliary_input) {

                        return Prover::process(pk, primary_input, auxiliary_input);
                    }

                    template<typename VerificationKey>
                    static inline bool verify(const VerificationKey &vk,
                                              const primary_input_type &primary_input,
                                              const proof_type &proof) {
                        return Verifier::process(vk, primary_input, proof);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_HPP
