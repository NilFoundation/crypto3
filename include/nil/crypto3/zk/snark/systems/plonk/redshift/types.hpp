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
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>

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

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the Redshift cheme.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        template <typename CommitmentSchemeType>
                        using proof_type = redshift_proof<CommitmentSchemeType>;

                        template <std::size_t k, typename ExpressionType>
                        struct preprocessed_data_type {

                            typedef ExpressionType expression_type;

                            constexpr static const typename FieldType::value_type omega = 
                                math::unity_root<FieldType>(math::detail::get_power_of_two(k));

                            std::vector<math::polynomial::polynom<typename FieldType::value_type>> selectors;
                            // S_sigma
                            std::vector<math::polynomial::polynom<typename FieldType::value_type>> permutations;
                            // S_id
                            std::vector<math::polynomial::polynom<typename FieldType::value_type>> identity_permutations;
                            // c
                            std::vector<ExpressionType> constraints;
                            
                            std::vector<math::polynomial::polynom<typename FieldType::value_type>> Lagrange_basis;

                            math::polynomial::polynom<typename FieldType::value_type> Z;

                        };

                        template<std::size_t AlphasAmount>
                        struct prover_fiat_shamir_heuristic_manifest {
                            enum challenges_ids { 
                                beta, 
                                gamma, 
                                alpha, 
                                upsilon = alpha + AlphasAmount 
                            };
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_REDSHIFT_TYPES_POLICY_HPP
