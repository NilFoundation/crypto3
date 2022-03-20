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

#ifndef CRYPTO3_ZK_PLONK_REDSHIFT_LOOKUP_ARGUMENT_HPP
#define CRYPTO3_ZK_PLONK_REDSHIFT_LOOKUP_ARGUMENT_HPP

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/zk/transcript/fiat_shamir.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/params.hpp>
#include <nil/crypto3/zk/snark/systems/plonk/redshift/detail/redshift_policy.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {
                template <typename FieldType, typename ParamsType>
                class redshift_lookup_argument {
                    using transcript_hash_type = typename ParamsType::transcript_hash_type;
                    using transcript_type = transcript::fiat_shamir_heuristic_sequential<transcript_hash_type>;

                    static constexpr std::size_t argument_size = 5;

                    typedef detail::redshift_policy<FieldType, ParamsType> policy_type;
                public:
                    struct prover_lookup_result {
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;
                    }
                    static inline prover_lookup_result prove_eval(
                        typename policy_type::constraint_system_type &constraint_system,
                        const typename policy_type::preprocessed_public_data_type preprocessed_data,
                        const plonk_assignment_table<FieldType, WitnessColumns, 
                                    SelectorColumns, PublicInputColumns, ConstantColumns> &plonk_columns,
                        transcript_type &transcript = transcript_type()) {
                        // $/theta = \challenge$
                        typename Fieldtype::value_type theta = transcript.template challenge<FieldType>();
                        // Construct lookup gates
                        const std::vector<plonk_gate<FieldType, plonk_lookup_constraint>> lookup_gates = constraint_system.lookup_gates();
                                                
                        std::array<math::polynomial<typename FieldType::value_type>, argument_size> F;

                        math::polynomial<typename FieldType::value_type> F_compr_input = {0};

                        math::polynomial<typename FieldType::value_type> F_compr_value = {0};

                        typename FieldType::value_type theta_acc = FieldType::value_type::one();

                        // Construct the input lookup compression and table compression values
                        /*for (std::size_t i = 0; i < lookup_gates.size(); i++) {
                            std::vector<typename FieldType::value_type> lookup_input_gate_result = {0};
                            std::vector<typename FieldType::value_type> lookup_value_gate_result = {0};

                            for (std::size_t j = 0; j < lookup_gates[i].constraints.size(); j++) {
                                lookup_input_gate_result = lookup_input_gate_result + lookup_gates[i].constraints[j].lookup_input.evaluate_lookup_input(plonk_columns) * theta_acc;
                                lookup_value_gate_result = lookup_value_gate_result + lookup_gates[i].constraints[j].lookup_value.evaluate_lookup_value(plonk_columns) * theta_acc;
                                theta_acc *= theta;
                            }
                            F_compr_value = F_compr_value + lookup_value_gate_result * column_polynomials.selector(lookup_gates[i].selector_index);
                            F_compr_input = F_compr_input + lookup_input_gate_result * column_polynomials.selector(lookup_gates[i].selector_index);
                        }*/
                        
                        //Produce the permutation polynomials $S_{\texttt{perm}}(X)$ and $A_{\texttt{perm}}(X)$


                        //Compute $V_L(X)$

                        //Calculate lookup-related numerators of the quotinent polynomial
                    }
                
                }
            }
        }
    }
}

#endif    // #ifndef CRYPTO3_ZK_PLONK_REDSHIFT_PERMUTATION_ARGUMENT_HPP
