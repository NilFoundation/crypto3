//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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

#ifndef CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP
#define CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /**
                 * A proof for the Placeholder cheme.
                 *
                 * While the proof has a structure, externally one merely opaquely produces,
                 * serializes/deserializes, and verifies proofs. We only expose some information
                 * about the structure for marshalling purposes.
                 */
                template<typename FieldType, typename ParamsType>
                struct placeholder_proof {
                    typedef FieldType field_type;
                    typedef ParamsType params_type;

                    using runtime_size_commitment_scheme_type =
                        typename ParamsType::runtime_size_commitment_scheme_type;
                    using witness_commitment_scheme_type = typename ParamsType::witness_commitment_scheme_type;
                    using public_input_commitment_scheme_type =
                        typename ParamsType::public_input_commitment_scheme_type;
                    using constant_commitment_scheme_type = typename ParamsType::constant_commitment_scheme_type;
                    using selector_commitment_scheme_type = typename ParamsType::selector_commitment_scheme_type;
                    using special_commitment_scheme_type = typename ParamsType::special_commitment_scheme_type;
                    using permutation_commitment_scheme_type = typename ParamsType::permutation_commitment_scheme_type;
                    using quotient_commitment_scheme_type = typename ParamsType::quotient_commitment_scheme_type;

                    struct evaluation_proof {
                        typename FieldType::value_type challenge;
                        typename FieldType::value_type lagrange_0;
                        typename witness_commitment_scheme_type::proof_type witness;

                        typename permutation_commitment_scheme_type::proof_type permutation;
                        typename runtime_size_commitment_scheme_type::proof_type quotient;
                        std::vector<typename quotient_commitment_scheme_type::proof_type> lookups;

                        typename runtime_size_commitment_scheme_type::proof_type id_permutation;
                        typename runtime_size_commitment_scheme_type::proof_type sigma_permutation;
                        typename public_input_commitment_scheme_type::proof_type public_input;
                        typename constant_commitment_scheme_type::proof_type constant;
                        typename selector_commitment_scheme_type::proof_type selector;
                        typename special_commitment_scheme_type::proof_type special_selectors;

                        bool operator==(const evaluation_proof &rhs) const {
                            return challenge == rhs.challenge && lagrange_0 == rhs.lagrange_0 &&
                                   witness == rhs.witness && permutation == rhs.permutation &&
                                   quotient == rhs.quotient && lookups == rhs.lookups &&
                                   id_permutation == rhs.id_permutation && sigma_permutation == rhs.sigma_permutation &&
                                   public_input == rhs.public_input && constant == rhs.constant &&
                                   selector == rhs.selector && special_selectors == rhs.special_selectors;
                        }
                        bool operator!=(const evaluation_proof &rhs) const {
                            return !(rhs == *this);
                        }
                    };

                    placeholder_proof() {
                    }

                    typename witness_commitment_scheme_type::commitment_type witness_commitment;

                    typename permutation_commitment_scheme_type::commitment_type v_perm_commitment;

                    typename permutation_commitment_scheme_type::commitment_type input_perm_commitment;

                    typename permutation_commitment_scheme_type::commitment_type value_perm_commitment;

                    typename permutation_commitment_scheme_type::commitment_type v_l_perm_commitment;

                    typename runtime_size_commitment_scheme_type::commitment_type T_commitment;

                    evaluation_proof eval_proof;

                    bool operator==(const placeholder_proof &rhs) const {
                        return witness_commitment == rhs.witness_commitment &&
                               v_perm_commitment == rhs.v_perm_commitment &&
                               input_perm_commitment == rhs.input_perm_commitment &&
                               value_perm_commitment == rhs.value_perm_commitment &&
                               v_l_perm_commitment == rhs.v_l_perm_commitment && T_commitment == rhs.T_commitment &&
                               eval_proof == rhs.eval_proof;
                    }
                    bool operator!=(const placeholder_proof &rhs) const {
                        return !(rhs == *this);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_PLACEHOLDER_PROOF_HPP
