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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/tbcs_ppzksnark/types_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /**
                     * A prover algorithm for the TBCS ppzkSNARK.
                     *
                     * Given a TBCS primary input X and a TBCS auxiliary input Y, this algorithm
                     * produces a proof (of knowledge) that attests to the following statement:
                     *               ``there exists Y such that C(X,Y)=0''.
                     * Above, C is the TBCS circuit that was given as input to the generator algorithm.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_prover {
                        using types_policy = detail::tbcs_ppzksnark_types_policy;
                    public:
                        using circuit_type = typename types_policy::circuit;
                        using primary_input_type = typename types_policy::primary_input;
                        using auxiliary_input_type = typename types_policy::auxiliary_input;

                        using proving_key_type = typename types_policy::proving_key;
                        using verification_key_type = typename types_policy::verification_key;
                        using processed_verification_key_type = typename types_policy::processed_verification_key;

                        using keypair_type = typename types_policy::keypair;
                        using proof_type = typename types_policy::proof;

                        static inline proof_type process(const proving_key_type &pk,
                                              const primary_input_type &primary_input,
                                              const auxiliary_input_type &auxiliary_input) {
                            typedef typename CurveType::scalar_field_type FieldType;

                            const uscs_variable_assignment<FieldType> uscs_va =
                                tbcs_to_uscs_witness_map<FieldType>(pk.circuit, primary_input, auxiliary_input);
                            const uscs_primary_input<FieldType> uscs_pi =
                                algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                            const uscs_auxiliary_input<FieldType> uscs_ai(
                                uscs_va.begin() + primary_input.size(),
                                uscs_va.end());    // TODO: faster to just change bacs_to_r1cs_witness_map into two :(
                            const typename uscs_ppzksnark<CurveType>::proof_type uscs_proof =
                                uscs_ppzksnark<CurveType>::prover(pk.uscs_pk, uscs_pi, uscs_ai);

                            return uscs_proof;
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP
