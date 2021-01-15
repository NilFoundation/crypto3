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
// @file Declaration of interfaces for a ppzkSNARK for R1CS with a security proof
// in the generic group (GG) model.
//
// This includes:
//- class for proving key
//- class for verification key
//- class for processed verification key
//- class for key pair (proving key & verification key)
//- class for proof
//- generator algorithm
//- prover algorithm
//- verifier algorithm (with strong or weak input consistency)
//- online verifier algorithm (with strong or weak input consistency)
//
// The implementation instantiates the protocol of \[Gro16].
//
//
// Acronyms:
//
//- R1CS = "Rank-1 Constraint Systems"
//- ppzkSNARK = "PreProcessing Zero-Knowledge Succinct Non-interactive ARgument of Knowledge"
//
// References:
//
//\[Gro16]:
// "On the Size of Pairing-based Non-interactive Arguments",
// Jens Groth,
// EUROCRYPT 2016,
// <https://eprint.iacr.org/2016/260>
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_R1CS_GG_PPZKSNARK_BASIC_POLICY_HPP
#define CRYPTO3_R1CS_GG_PPZKSNARK_BASIC_POLICY_HPP

#include <memory>

#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/proving_key.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/verification_key.hpp>
#include <nil/crypto3/zk/snark/proof_systems/detail/ppzksnark/r1cs_gg_ppzksnark/keypair.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename CurveType>
                    struct r1cs_gg_ppzksnark_basic_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef r1cs_constraint_system<typename CurveType::scalar_field_type> constraint_system;

                        typedef r1cs_primary_input<typename CurveType::scalar_field_type> primary_input;

                        typedef r1cs_auxiliary_input<typename CurveType::scalar_field_type> auxiliary_input;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_proving_key<CurveType> proving_key;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the R1CS GG-ppzkSNARK.
                         */
                        typedef r1cs_gg_ppzksnark_verification_key<CurveType> verification_key;

                        /************************ Processed verification key *************************/

                        /**
                         * A processed verification key for the R1CS GG-ppzkSNARK.
                         *
                         * Compared to a (non-processed) verification key, a processed verification key
                         * contains a small constant amount of additional pre-computed information that
                         * enables a faster verification time.
                         */
                        typedef r1cs_gg_ppzksnark_processed_verification_key<CurveType> processed_verification_key;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the R1CS GG-ppzkSNARK, which consists of a proving key and a verification key.
                         */
                        typedef r1cs_gg_ppzksnark_keypair<proving_key, verification_key> keypair;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the R1CS GG-ppzkSNARK.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        struct proof {

                            typename CurveType::g1_type::value_type g_A;
                            typename CurveType::g2_type::value_type g_B;
                            typename CurveType::g1_type::value_type g_C;

                            proof() {
                                // invalid proof with valid curve points
                                this->g_A = CurveType::g1_type::value_type::one();
                                this->g_B = CurveType::g2_type::value_type::one();
                                this->g_C = CurveType::g1_type::value_type::one();
                            }
                            proof(typename CurveType::g1_type::value_type &&g_A,
                                  typename CurveType::g2_type::value_type &&g_B,
                                  typename CurveType::g1_type::value_type &&g_C) :
                                g_A(std::move(g_A)),
                                g_B(std::move(g_B)), g_C(std::move(g_C)) {};

                            std::size_t G1_size() const {
                                return 2;
                            }

                            std::size_t G2_size() const {
                                return 1;
                            }

                            std::size_t size_in_bits() const {
                                return G1_size() * CurveType::g1_type::value_bits +
                                       G2_size() * CurveType::g2_type::value_bits;
                            }

                            bool is_well_formed() const {
                                return (g_A.is_well_formed() && g_B.is_well_formed() && g_C.is_well_formed());
                            }

                            bool operator==(const proof &other) const {
                                return (this->g_A == other.g_A && this->g_B == other.g_B && this->g_C == other.g_C);
                            }
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_R1CS_GG_PPZKSNARK_TYPES_POLICY_HPP
