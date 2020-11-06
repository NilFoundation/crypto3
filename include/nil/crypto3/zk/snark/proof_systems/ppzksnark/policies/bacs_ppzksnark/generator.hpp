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

#ifndef CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP

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
                     * A generator algorithm for the BACS ppzkSNARK.
                     *
                     * Given a BACS circuit C, this algorithm produces proving and verification keys for C.
                     */
                    struct bacs_ppzksnark_generator {

                        template<typename CurveType>
                        keypair_type operator()(const circuit_type &circuit) {
                            typedef typename CurveType::scalar_field_type field_type;

                            const r1cs_constraint_system<field_type> r1cs_cs =
                                bacs_to_r1cs_instance_map<field_type>(circuit);
                            const typename r1cs_ppzksnark<CurveType>::keypair_type r1cs_keypair =
                                r1cs_ppzksnark<CurveType>::generator(r1cs_cs);

                            return keypair_type(proving_key(circuit, r1cs_keypair.pk), r1cs_keypair.vk);
                        }
                    };

                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BACS_PPZKSNARK_BASIC_GENERATOR_HPP
