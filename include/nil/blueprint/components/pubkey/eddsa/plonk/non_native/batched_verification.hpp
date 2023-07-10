//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the EDDSA25519 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_PUBKEY_EDDSA_PLONK_NON_NATIVE_BATCHED_VERIFICATION_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_PUBKEY_EDDSA_PLONK_NON_NATIVE_BATCHED_VERIFICATION_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/non_native/algebra/fields/plonk/ed25519.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type, std::size_t k,
                 std::size_t... WireIndexes>
            class batched_verification;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams,
                     typename CurveType,
                     typename Ed25519Type,
                     std::size_t k,
                     std::size_t W0,
                     std::size_t W1,
                     std::size_t W2,
                     std::size_t W3,
                     std::size_t W4,
                     std::size_t W5,
                     std::size_t W6,
                     std::size_t W7,
                     std::size_t W8>
            class batched_verification<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                   CurveType,
                                                   Ed25519Type,
                                                   k,
                                                   W0,
                                                   W1,
                                                   W2,
                                                   W3,
                                                   W4,
                                                   W5,
                                                   W6,
                                                   W7,
                                                   W8> {

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

                using ed25519_component = eddsa25519<ArithmetizationType, CurveType, Ed25519Type,
                W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                
                using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
                using var_ec_point = typename ed25519_component::params_type::var_ec_point;
                using signature = typename ed25519_component::params_type::signature;
                constexpr static const std::size_t selector_seed = 0xfcc7;

            public:
                constexpr static const std::size_t rows_amount = ed25519_component::rows_amount*k;

                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    std::array<signature, k> signatures;
                    std::array<var_ec_point, k> public_keys;
                    std::array<var, 4> M;
                };

                struct result_type {
                    result_type(std::size_t component_start_row) {
                    }
                };

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    for (std::size_t i = 0; i < k; i++){
                        ed25519_component::generate_assignments(assignment, {params.signatures[i], params.public_keys[i], params.M}, row);
                        row += ed25519_component::rows_amount;
                    }
                    return result_type(component_start_row);
                }

                static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                    const params_type &params,
                                                    const std::size_t component_start_row){
                    std::size_t row = component_start_row;
                    for (std::size_t i = 0; i < k; i++){
                        ed25519_component::generate_circuit(bp, assignment, {params.signatures[i], params.public_keys[i], params.M}, row);
                        row += ed25519_component::rows_amount;
                    }
                    return result_type(component_start_row);
                }

            private:

                static void generate_gates(
                    blueprint<ArithmetizationType> &bp,
                    blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                    const params_type &params,
                    const std::size_t first_selector_index) {
                    
                }

                static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                      blueprint_public_assignment_table<ArithmetizationType> &public_assignment,
                                                      const params_type &params,
                                                      std::size_t component_start_row) {
                }

                static void generate_lookup_table(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t component_start_row) {
                
                    std::size_t row = component_start_row;
                    std::size_t n = (1 << 16);
                    for(std::size_t i = 0; i < 2; i++) {
                        assignment.constant(1)[i] = 0;
                    }
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_PUBKEY_EDDSA_PLONK_NON_NATIVE_BATCHED_VERIFICATION_HPP