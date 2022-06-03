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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename FieldType, typename KimchiParamsType>
                struct kimchi_lookup_evaluations {
                    /// sorted lookup table polynomial
                    // pub sorted: Vec<Field>,
                    // /// lookup aggregation polynomial
                    // pub aggreg: Field,
                    // // TODO: May be possible to optimize this away?
                    // /// lookup table polynomial
                    // pub table: Field,

                    // /// Optionally, a runtime table polynomial.
                    // pub runtime: Option<Field>,
                    kimchi_lookup_evaluations() {
                    }
                };

                template<typename FieldType, typename KimchiParamsType>
                struct kimchi_proof_evaluations {
                    using var = snark::plonk_variable<FieldType>;
                    // witness polynomials
                    std::array<var, KimchiParamsType::witness_columns> w;
                    // permutation polynomial
                    var z;
                    // permutation polynomials
                    // (PERMUTS-1 evaluations because the last permutation is only used in commitment form)
                    std::array<var, KimchiParamsType::permut_size - 1> s;
                    // /// lookup-related evaluations
                    kimchi_lookup_evaluations<FieldType, KimchiParamsType> lookup;
                    // /// evaluation of the generic selector polynomial
                    var generic_selector;
                    // /// evaluation of the poseidon selector polynomial
                    var poseidon_selector;

                    kimchi_proof_evaluations() {
                    }
                };

                template<typename BlueprintFieldType, typename KimchiParamsType,
                    std::size_t EvalRounds>
                struct kimchi_proof_scalar {
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t chal_per_round = 2;

                    std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, 2> proof_evals;
                    var ft_eval;
                    std::array<var, KimchiParamsType::public_input_size> public_input;
                    std::array<var, EvalRounds> prev_challenges;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP