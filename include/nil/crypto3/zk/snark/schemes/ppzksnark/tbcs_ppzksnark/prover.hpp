//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP
#define CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP

#include <nil/crypto3/zk/snark/relations/circuit_satisfaction_problems/tbcs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/uscs_ppzksnark.hpp>
#include <nil/crypto3/zk/snark/reductions/tbcs_to_uscs.hpp>
#include <nil/crypto3/zk/snark/schemes/ppzksnark/tbcs_ppzksnark/detail/basic_policy.hpp>

#include <nil/crypto3/zk/snark/algorithms/prove.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

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
                    typedef detail::tbcs_ppzksnark_policy<CurveType> policy_type;

                public:
                    typedef typename policy_type::circuit_type circuit_type;
                    typedef typename policy_type::primary_input_type primary_input_type;
                    typedef typename policy_type::auxiliary_input_type auxiliary_input_type;

                    typedef typename policy_type::proving_key_type proving_key_type;
                    typedef typename policy_type::verification_key_type verification_key_type;
                    typedef typename policy_type::processed_verification_key_type processed_verification_key_type;

                    typedef typename policy_type::keypair_type keypair_type;
                    typedef typename policy_type::proof_type proof_type;

                    static inline proof_type process(const proving_key_type &pk,
                                                     const primary_input_type &primary_input,
                                                     const auxiliary_input_type &auxiliary_input) {
                        typedef typename CurveType::scalar_field_type FieldType;

                        const uscs_variable_assignment<FieldType> uscs_va =
                            reductions::tbcs_to_uscs<FieldType>::witness_map(pk.circuit, primary_input, auxiliary_input);
                        const uscs_primary_input<FieldType> uscs_pi =
                            algebra::convert_bit_vector_to_field_element_vector<FieldType>(primary_input);
                        const uscs_auxiliary_input<FieldType> uscs_ai(
                            uscs_va.begin() + primary_input.size(),
                            uscs_va.end());    // TODO: faster to just change bacs_to_r1cs<field_type>::witness_map into two :(

                        return prove<uscs_ppzksnark<CurveType>>(pk.uscs_pk, uscs_pi, uscs_ai);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_TBCS_PPZKSNARK_BASIC_PROVER_HPP
