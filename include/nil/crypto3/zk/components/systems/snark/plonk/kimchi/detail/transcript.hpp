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

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/sponge.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                
                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class kimchi_transcript;

                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         typename CurveType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class kimchi_transcript<
                    snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams>,
                    CurveType,
                    W0, W1, W2, W3, W4,
                    W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14>{

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    kimchi_sponge<ArithmetizationType, CurveType,
                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> sponge;

                public:
                    constexpr static const std::size_t required_rows_amount = 1;

                    struct public_params_type {
                    };

                    struct private_params_type {
                        
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp,
                        std::size_t components_amount = 1){
                        return bp.allocate_rows(required_rows_amount *
                            components_amount);
                    }

                    void init_assignment(blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            std::size_t &component_start_row) {
                        
                    }

                    void init_generate_constraints(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const var &zero,
                        const std::size_t &component_start_row) {
                            
                    }

                    void absorb_assignment(blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            var absorbing_value,
                            std::size_t &component_start_row) {
                        
                    }

                    void absorb_generate_constraints(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const var &zero,
                        const std::size_t &component_start_row) {
                            
                    }

                    var squeeze_assignment(blueprint_private_assignment_table<ArithmetizationType>
                            &private_assignment,
                            blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                            var absorbing_value,
                            std::size_t &component_start_row) {

                    }

                    void squeeze_generate_constraints(blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                        const var &zero,
                        const std::size_t &component_start_row) {
                            
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_KIMCHI_TRANSCRIPT_HPP