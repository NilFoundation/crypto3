//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for auxiliary components for the ED25519 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_ED25519_HPP
#define CRYPTO3_ZK_BLUEPRINT_ED25519_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/fixed_base_multiplication_edwards2519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/variable_base_multiplication_edwards2519.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/range.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/decomposition.hpp>
#include <nil/crypto3/zk/components/non_native/algebra/fields/plonk/addition_edwards2519.hpp>
#include <nil/crypto3/zk/components/hashes/sha256/plonk/sha256.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType,
                         typename CurveType,
                         std::size_t... WireIndexes>
                class ed25519;

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
                         std::size_t W8>
                class ed25519<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                                       CurveType,
                                                       W0,
                                                       W1,
                                                       W2,
                                                       W3,
                                                       W4,
                                                       W5,
                                                       W6,
                                                       W7,
                                                       W8> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType,
                        ArithmetizationParams> ArithmetizationType;

                    using sha512_component = sha512<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using fixed_base_multiplication_edwards25519_component = fixed_base_multiplication_edwards25519<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using variable_base_multiplication_edwards25519_component = variable_base_multiplication_edwards25519<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using range_component = range<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;
                    using addition_edwards25519_component = addition_edwards25519<ArithmetizationType, BlueprintFieldType,
                    W0, W1, W2, W3, W4, W5, W6, W7, W8>;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    

                public:

                    constexpr static const std::size_t required_rows_amount = 36932;

                    struct params_type {
                        struct var_ec_point {
                            var x;
                            var y;
                        };
                        
                        var_ec_point R;
                        var_ec_point A;
                        var_ec_point B;
                        var s;
                    };

                    struct allocated_data_type {
                        allocated_data_type() {
                            previously_allocated = false;
                        }

                        // TODO access modifiers
                        bool previously_allocated;
                        std::array<std::size_t, 1> selectors;
                    };

                    struct result_type {

                        result_type(const std::size_t &component_start_row) {
                        }
                    };

                    static std::size_t allocate_rows (blueprint<ArithmetizationType> &bp){
                        return bp.allocate_rows(required_rows_amount);
                    }

                    static result_type generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {

                        generate_gates(bp, assignment, params, allocated_data, component_start_row);
                        generate_copy_constraints(bp, assignment, params, component_start_row);
                        return result_type(component_start_row);
                    }

                    static result_type generate_assignments(
                        blueprint_assignment_table<ArithmetizationType>
                            &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;

                        range_component::params_type range_params = {params.s}
                        range_component::generate_assignments(assigment, range_params, component_start_row);
                        row = row + range_component::required_rows_amount;

                        sha512::params_type sha_params = {params.R, params.A, params.B};
                        auto sha_result = sha512_component::generate_assignments(assigment, sha_params, component_start_row);
                        row = row + sha512_component::required_rows_amount;

                        decomposition::params_type decomposition_params = {sha_result.output};
                        auto decomposition_result = decomposition_component::generate_assignments(assigment, decomposition_params, component_start_row);
                        row = row + decomposition_component::required_rows_amount;

                        fixed_base_multiplication_edwards25519::params_type fixed_base_multiplication_edwards25519_params = {params.s, params.B};
                        auto fixed_base_multiplication_edwards25519_result = fixed_base_multiplication_edwards25519_component::generate_assignments(
                            assigment, fixed_base_multiplication_edwards25519_params, component_start_row);
                        row = row + fixed_base_multiplication_edwards25519::required_rows_amount;

                        variable_base_multiplication_edwards25519::params_type variable_base_multiplication_edwards25519_params = {decomposition_result.output[0], params.A};
                        auto fixed_base_multiplication_edwards25519_result = fixed_base_multiplication_edwards25519_component::generate_assignments(
                            assigment, variable_base_multiplication_edwards25519_params, component_start_row);
                        row = row + variable_base_multiplication_edwards25519::required_rows_amount;    

                        addition_edwards25519::params_type addition_edwards25519_params = {fixed_base_multiplication_edwards25519_result.output[0], params.R};
                        addition_edwards25519_component::generate_assignments(assigment, addition_edwards25519_params, component_start_row);

                        return result_type(component_start_row);
                    }

                private:

                    static void generate_gates(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        allocated_data_type &allocated_data,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;

                        range_component::generate_gates(assigment, allocated_data, component_start_row);
                        row = row + range_component::required_rows_amount;

                        sha512_component::generate_gates(assigment, allocated_data, component_start_row);
                        row = row + sha512_component::required_rows_amount;

                        decomposition_component::generate_gates(assigment, allocated_data, component_start_row);
                        row = row + decomposition_component::required_rows_amount;

                        fixed_base_multiplication_edwards25519_component::generate_gates(
                            assigment, allocated_data, component_start_row);
                        row = row + fixed_base_multiplication_edwards25519_component::required_rows_amount;

                        variable_base_multiplication_edwards25519_component::generate_gates(
                            assigment, allocated_data, component_start_row);
                        row = row + variable_base_multiplication_edwards25519_component::required_rows_amount;
                        addition_edwards25519_component::generate_gates(assigment, allocated_data, component_start_row);

                        return result_type(component_start_row);
                    }
                        
                        
                    }

                    static void generate_copy_constraints(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        const std::size_t &component_start_row) {
                        std::size_t row = component_start_row;
                                                std::size_t row = component_start_row;

                        range_component::generate_copy_constraints(assigment, allocated_data, component_start_row);
                        row = row + range_component::required_rows_amount;

                        sha512_component::generate_copy_constraints(assigment, allocated_data, component_start_row);
                        row = row + sha512_component::required_rows_amount;

                        decomposition_component::generate_copy_constraints(assigment, allocated_data, component_start_row);
                        row = row + decomposition_component::required_rows_amount;

                        fixed_base_multiplication_edwards25519_component::generate_copy_constraints(
                            assigment, allocated_data, component_start_row);
                        row = row + fixed_base_multiplication_edwards25519_component::required_rows_amount;

                        variable_base_multiplication_edwards25519_component::generate_copy_constraints(
                            assigment, allocated_data, component_start_row);
                        row = row + variable_base_multiplication_edwards25519_component::required_rows_amount;
                        addition_edwards25519_component::generate_copy_constraints(assigment, allocated_data, component_start_row);
                        
                        
                    }

                    
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP