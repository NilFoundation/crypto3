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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_PROOF_SCALAR_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_PROOF_SCALAR_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/batch_verify_scalar_field.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename BlueprintFieldType,
                         typename ArithmetizationType,
                         typename KimchiCommitmentParamsType>
                struct batch_evaluation_proof_scalar {
                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType, KimchiCommitmentParamsType>;
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    // pub sponge: EFqSponge,
                    // pub evaluations: Vec<Evaluation<G>>,
                    // /// vector of evaluation points
                    // pub evaluation_points: Vec<ScalarField<G>>,
                    // /// scaling factor for evaluation point powers
                    // pub xi: ScalarField<G>,
                    // /// scaling factor for polynomials
                    // pub r: ScalarField<G>,
                    // /// batched opening proof
                    // pub opening: &'a OpeningProof<G>,
                    var cip;
                    typename proof_binding::fq_sponge_output fq_output;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_BATCH_PROOF_SCALAR_HPP