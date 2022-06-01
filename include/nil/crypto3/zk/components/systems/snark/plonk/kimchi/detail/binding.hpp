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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_BINDING_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_BINDING_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, 
                    typename BlueprintFieldType,
                    typename KimchiCommitmentParamsType>
                struct binding {
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    template<typename DataType>
                    struct fr_data {

                    };

                    template<typename DataType>
                    struct fq_data {

                    };

                    struct fq_sponge_output {
                        var joint_combiner;
                        var beta;    // beta and gamma can be combined from limbs in the base circuit
                        var gamma;
                        var alpha;
                        var zeta;
                        var fq_digest;    // TODO overflow check
                        std::array<var, KimchiCommitmentParamsType::eval_rounds> challenges;
                        var c;


                        static fq_sponge_output
                            allocate_fq_output(blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                typename BlueprintFieldType::value_type joint_combiner,
                                typename BlueprintFieldType::value_type beta,
                                typename BlueprintFieldType::value_type gamma,
                                typename BlueprintFieldType::value_type alpha,
                                typename BlueprintFieldType::value_type zeta,
                                typename BlueprintFieldType::value_type fq_digest,
                                std::array<typename BlueprintFieldType::value_type,
                                    KimchiCommitmentParamsType::eval_rounds> challenges,
                                typename BlueprintFieldType::value_type c) {

                            std::array<var, KimchiCommitmentParamsType::eval_rounds> chals;
                            for (std::size_t i = 0; i < KimchiCommitmentParamsType::eval_rounds; i++) {
                                chals[i] = assignment.allocate_public_input(challenges[i]);
                            }

                            return fq_sponge_output {
                                assignment.allocate_public_input(joint_combiner),
                                assignment.allocate_public_input(beta),
                                assignment.allocate_public_input(gamma),
                                assignment.allocate_public_input(alpha),
                                assignment.allocate_public_input(zeta),
                                assignment.allocate_public_input(fq_digest),
                                chals,
                                assignment.allocate_public_input(c)
                            };
                        }
                    };
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_BINDING_HPP