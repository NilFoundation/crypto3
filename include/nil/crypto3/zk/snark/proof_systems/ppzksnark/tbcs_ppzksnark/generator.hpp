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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/tbcs_ppzksnark/detail/basic_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace policies {

                    /**
                     * A generator algorithm for the TBCS ppzkSNARK.
                     *
                     * Given a TBCS circuit C, this algorithm produces proving and verification keys for C.
                     */
                    template<typename CurveType>
                    class tbcs_ppzksnark_generator {
                        typedef detail::tbcs_ppzksnark_types_policy<CurveType> policy_type;

                    public:
                        typedef typename policy_type::circuit circuit_type;
                        typedef typename policy_type::primary_input primary_input_type;
                        typedef typename policy_type::auxiliary_input auxiliary_input_type;

                        typedef typename policy_type::proving_key proving_key_type;
                        typedef typename policy_type::verification_key verification_key_type;
                        typedef typename policy_type::processed_verification_key processed_verification_key_type;

                        typedef typename policy_type::keypair keypair_type;
                        typedef typename policy_type::proof proof_type;

                        static inline keypair_type process(const circuit_type &circuit) {
                            typedef typename CurveType::scalar_field_type field_type;

                            const uscs_constraint_system<field_type> uscs_cs =
                                tbcs_to_uscs_instance_map<field_type>(circuit);
                            const typename uscs_ppzksnark<CurveType>::keypair_type uscs_keypair =
                                uscs_ppzksnark<CurveType>::generator(uscs_cs);

                            return keypair_type(proving_key_type(circuit, uscs_keypair.pk), uscs_keypair.vk);
                        }
                    };
                }    // namespace policies
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_GENERATOR_HPP
