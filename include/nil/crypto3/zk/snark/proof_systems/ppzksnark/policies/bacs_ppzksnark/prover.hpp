//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
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
// @file Declaration of interfaces for a ppzkSNARK for BACS.
//
// This includes:
// - class for proving key
// - class for verification key
// - class for processed verification key
// - class for key pair (proving key & verification key)
// - class for proof
// - generator algorithm
// - prover algorithm
// - verifier algorithm (with strong or weak input consistency)
// - online verifier algorithm (with strong or weak input consistency)
//
// The implementation is a straightforward combination of:
// (1) a BACS-to-R1CS reduction, and
// (2) a ppzkSNARK for R1CS.
//
//
// Acronyms:
//
// - BACS = "Bilinear Arithmetic Circuit Satisfiability"
// - R1CS = "Rank-1 Constraint System"
// - ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_PROVER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/bacs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/bacs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    using types_policy = detail::bacs_ppzksnark_types_policy;

                    using circuit_type = typename types_policy::circuit;
                    using primary_input_type = typename types_policy::primary_input;
                    using auxiliary_input_type = typename types_policy::auxiliary_input;

                    using proving_key_type = typename types_policy::proving_key;
                    using verification_key_type = typename types_policy::verification_key;
                    using processed_verification_key_type = typename types_policy::processed_verification_key;

                    using keypair_type = typename types_policy::keypair;
                    using proof_type = typename types_policy::proof;
                    /**
                     * A prover algorithm for the BACS ppzkSNARK.
                     *
                     * Given a BACS primary input X and a BACS auxiliary input Y, this algorithm
                     * produces a proof (of knowledge) that attests to the following statement:
                     *               ``there exists Y such that C(X,Y)=0''.
                     * Above, C is the BACS circuit that was given as input to the generator algorithm.
                     */
                    struct bacs_ppzksnark_prover {

                        template<typename CurveType>
                        proof_type operator()(const proving_key_type &proving_key,
                                              const primary_input_type &primary_input,
                                              const auxiliary_input_type &auxiliary_input) {

                            typedef typename CurveType::scalar_field_type field_type;

                            const r1cs_variable_assignment<field_type> r1cs_va =
                                bacs_to_r1cs_witness_map<field_type>(proving_key.circuit, primary_input, auxiliary_input);
                            const r1cs_auxiliary_input<field_type> r1cs_ai(
                                r1cs_va.begin() + primary_input.size(),
                                r1cs_va.end());    // TODO: faster to just change bacs_to_r1cs_witness_map into two :(
                            const typename r1cs_ppzksnark<CurveType>::proof_type r1cs_proof =
                                r1cs_ppzksnark<CurveType>::prover(proving_key.r1cs_pk, primary_input, r1cs_ai);

                            return r1cs_proof;
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_PROVER_HPP
