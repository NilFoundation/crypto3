//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/algorithms/unity_root.hpp>
#include <nil/crypto3/math/detail/field_utils.hpp>
#include <nil/crypto3/math/domains/evaluation_domain.hpp>
#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/zk/snark/relations/plonk/plonk.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/proof.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                namespace detail {
                    template<typename FieldType, typename RedshiftParams>
                    struct redshift_policy {

                        constexpr static const std::size_t witness_columns = RedshiftParams::witness_columns;
                        constexpr static const std::size_t public_input_columns = 
                            RedshiftParams::public_input_columns;
                        constexpr static const std::size_t constant_columns = RedshiftParams::constant_columns;
                        constexpr static const std::size_t selector_columns = RedshiftParams::selector_columns;                       

                        /******************************** Params ********************************/

                        /**
                         * Below are various template aliases (used for convenience).
                         */

                        typedef plonk_constraint_system<FieldType> constraint_system_type;

                        typedef RedshiftParams redshift_params_type;

                        typedef plonk_assignment_table<FieldType, witness_columns,
                            public_input_columns, constant_columns, selector_columns> variable_assignment_type;

                        typedef detail::plonk_evaluation_map<plonk_variable<FieldType>> evaluation_map;

                        /*********************************** Proof ***********************************/

                        /**
                         * A proof for the Redshift cheme.
                         *
                         * While the proof has a structure, externally one merely opaquely produces,
                         * serializes/deserializes, and verifies proofs. We only expose some information
                         * about the structure for statistics purposes.
                         */
                        template<typename CommitmentSchemeTypeWitness, typename CommitmentSchemeTypePermutation,
                                 typename CommitmentSchemeTypeQuotient, typename CommitmentSchemeTypePublic>
                        using proof_type =
                            redshift_proof<FieldType, CommitmentSchemeTypeWitness, CommitmentSchemeTypePermutation,
                                           CommitmentSchemeTypeQuotient, CommitmentSchemeTypePublic>;

                        struct preprocessed_public_data_type {
                            typedef typename RedshiftParams::commitment_scheme_public_type
                                commitment_scheme_public_type;

                            struct public_precommitments {
                                std::vector<typename commitment_scheme_public_type::precommitment_type> id_permutation;
                                std::vector<typename commitment_scheme_public_type::precommitment_type> sigma_permutation;
                                std::array<typename commitment_scheme_public_type::precommitment_type, public_input_columns> public_input;
                                std::array<typename commitment_scheme_public_type::precommitment_type, constant_columns> constant;
                                std::array<typename commitment_scheme_public_type::precommitment_type, selector_columns> selector;
                                std::array<typename commitment_scheme_public_type::precommitment_type, 2> special_selectors;
                            };

                            struct public_commitments {
                                std::vector<typename commitment_scheme_public_type::commitment_type> id_permutation;
                                std::vector<typename commitment_scheme_public_type::commitment_type> sigma_permutation;
                                std::array<typename commitment_scheme_public_type::commitment_type, public_input_columns> public_input;
                                std::array<typename commitment_scheme_public_type::commitment_type, constant_columns> constant;
                                std::array<typename commitment_scheme_public_type::commitment_type, selector_columns> selector;
                                std::array<typename commitment_scheme_public_type::commitment_type, 2> special_selectors;
                            };

                            // both prover and verifier use this data
                            // fields outside of the common_data_type are used by prover
                            struct common_data_type {
                                std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;

                                math::polynomial<typename FieldType::value_type> Z;
                                math::polynomial<typename FieldType::value_type> lagrange_0;

                                public_commitments commitments;
                            };

                            plonk_public_polynomial_table<FieldType, public_input_columns, 
                                constant_columns, selector_columns> public_polynomial_table;

                            // S_sigma
                            std::vector<math::polynomial<typename FieldType::value_type>> permutation_polynomials;
                            // S_id
                            std::vector<math::polynomial<typename FieldType::value_type>> identity_polynomials;

                            math::polynomial<typename FieldType::value_type> q_last; // TODO: move to common data
                            math::polynomial<typename FieldType::value_type> q_blind;

                            public_precommitments precommitments;

                            common_data_type common_data;
                        };

                        struct preprocessed_private_data_type {

                            std::shared_ptr<math::evaluation_domain<FieldType>> basic_domain;

                            plonk_private_polynomial_table<FieldType, RedshiftParams::witness_columns> private_polynomial_table;
                        };
                    };
                }    // namespace detail
            }        // namespace snark
        }            // namespace zk
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PLONK_REDSHIFT_TYPES_POLICY_HPP
