//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of types for Redshift PLONK scheme.
//
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PLONK_REDSHIFT_TYPES_POLICY_HPP
#define CRYPTO3_PLONK_REDSHIFT_TYPES_POLICY_HPP

#include <nil/crypto3/math/polynomial/polynom.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {

                    template<typename FieldType, std::size_t WiresAmount>
                    struct redshift_types_policy {

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef plonk_constraint_system<FieldType, WiresAmount> constraint_system_type;

                        typedef plonk_primary_input<FieldType> primary_input_type;

                        typedef plonk_auxiliary_input<FieldType> auxiliary_input_type;

                        /******************************** Proving key ********************************/

                        /**
                         * A proving key for the Redshift cheme.
                         */
                        typedef redshift_proving_key<FieldType, constraint_system_type> proving_key_type;

                        /******************************* Verification key ****************************/

                        /**
                         * A verification key for the Redshift cheme.
                         */
                        typedef redshift_verification_key<FieldType> verification_key_type;

                        /********************************** Key pair *********************************/

                        /**
                         * A key pair for the Redshift cheme, which consists of a proving key and a verification key.
                         */
                        typedef plonk_ppzksnark_keypair<proving_key_type, verification_key_type> keypair_type;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the Redshift cheme.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        template <typename CommitmentSchemeType>
                        typedef redshift_proof<CommitmentSchemeType> proof_type;

                        template <std::size_t k>
                        struct preprocessed_data_type {

                            constexpr static const typename FieldType::value_type omega = 
                                math::unity_root(get_power_of_two(k));

                            std::vector<math::polynomial::polynom> selectors;
                            // S_sigma
                            std::vector<math::polynomial::polynom> permutations;
                            // S_id
                            std::vector<math::polynomial::polynom> identity_permutations;
                            // c
                            std::vector<math::polynomial::polynom> constraints;
                            
                            std::vector<math::polynomial::polynom> Lagrange_basis;

                        };

                        template<std::size_t AlphasAmount = 6>
                        struct prover_fiat_shamir_heuristic_manifest {
                            enum challenges_ids { beta, gamma, alpha, upsilon = alpha + AlphasAmount };
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_REDSHIFT_TYPES_POLICY_HPP
