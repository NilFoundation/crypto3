//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Noam Yemini <@NoamDev at GitHub>
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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_BLUEPRINT_R1CS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_BLUEPRINT_R1CS_HPP

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/arithmetization/constraint_satisfaction_problems/r1cs.hpp>

#include <nil/blueprint/blueprint/r1cs/detail/r1cs/blueprint_variable.hpp>
#include <nil/blueprint/blueprint/r1cs/detail/r1cs/blueprint_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {

            template<typename ArithmetizationType, std::size_t... BlueprintParams>
            class blueprint;

            template<typename BlueprintFieldType>
            class blueprint<crypto3::zk::snark::r1cs_constraint_system<BlueprintFieldType>> {
                typedef zk::snark::r1cs_constraint_system<BlueprintFieldType> ArithmetizationType;

                zk::snark::r1cs_variable_assignment<BlueprintFieldType>
                    values; /* values[0] will hold the value of the first
               allocated variable of the blueprint, *NOT* constant 1 */
                typename BlueprintFieldType::value_type constant_term;

                typename math::linear_variable<BlueprintFieldType>::index_type next_free_var;
                typename detail::blueprint_linear_combination<ArithmetizationType>::index_type next_free_lc;
                std::vector<typename BlueprintFieldType::value_type> lc_values;
                zk::snark::r1cs_constraint_system<BlueprintFieldType> constraint_system;

            public:
                // typedef BlueprintFieldType field_type;

                using value_type = detail::blueprint_variable<ArithmetizationType>;

                blueprint() {
                    constant_term = BlueprintFieldType::value_type::one();

                    next_free_var = 1; /* to account for constant 1 term */
                    next_free_lc = 0;
                }

                void clear_values() {
                    std::fill(values.begin(), values.end(), BlueprintFieldType::value_type::zero());
                }

                typename BlueprintFieldType::value_type &val(const value_type &var) {
                    assert(var.index <= values.size());
                    return (var.index == 0 ? constant_term : values[var.index - 1]);
                }

                typename BlueprintFieldType::value_type val(const value_type &var) const {
                    assert(var.index <= values.size());
                    return (var.index == 0 ? constant_term : values[var.index - 1]);
                }

                typename BlueprintFieldType::value_type &
                    lc_val(const detail::blueprint_linear_combination<ArithmetizationType> &lc) {
                    if (lc.is_variable) {
                        return this->val(value_type(lc.index));
                    } else {
                        assert(lc.index < lc_values.size());
                        return lc_values[lc.index];
                    }
                }

                typename BlueprintFieldType::value_type
                    lc_val(const detail::blueprint_linear_combination<ArithmetizationType> &lc) const {
                    if (lc.is_variable) {
                        return this->val(value_type(lc.index));
                    } else {
                        assert(lc.index < lc_values.size());
                        return lc_values[lc.index];
                    }
                }

                void add_r1cs_constraint(const zk::snark::r1cs_constraint<BlueprintFieldType> &constr) {
                    constraint_system.constraints.emplace_back(constr);
                }

                bool is_satisfied() const {
                    return constraint_system.is_satisfied(primary_input(), auxiliary_input());
                }

                std::size_t num_constraints() const {
                    return constraint_system.num_constraints();
                }

                std::size_t num_inputs() const {
                    return constraint_system.num_inputs();
                }

                std::size_t num_variables() const {
                    return next_free_var - 1;
                }

                void set_input_sizes(const std::size_t primary_input_size) {
                    assert(primary_input_size <= num_variables());
                    constraint_system.primary_input_size = primary_input_size;
                    constraint_system.auxiliary_input_size = num_variables() - primary_input_size;
                }

                zk::snark::r1cs_variable_assignment<BlueprintFieldType> full_variable_assignment() const {
                    return values;
                }

                zk::snark::r1cs_primary_input<BlueprintFieldType> primary_input() const {
                    return zk::snark::r1cs_primary_input<BlueprintFieldType>(values.begin(), values.begin() + num_inputs());
                }

                zk::snark::r1cs_auxiliary_input<BlueprintFieldType> auxiliary_input() const {
                    return zk::snark::r1cs_auxiliary_input<BlueprintFieldType>(values.begin() + num_inputs(), values.end());
                }

                zk::snark::r1cs_constraint_system<BlueprintFieldType> get_constraint_system() const {
                    return constraint_system;
                }

                friend class detail::blueprint_variable<ArithmetizationType>;
                friend class detail::blueprint_linear_combination<ArithmetizationType>;

            private:
                typename math::linear_variable<BlueprintFieldType>::index_type allocate_var_index() {
                    ++constraint_system.auxiliary_input_size;
                    values.emplace_back(BlueprintFieldType::value_type::zero());
                    return next_free_var++;
                }

                typename detail::blueprint_linear_combination<ArithmetizationType>::index_type allocate_lc_index() {
                    lc_values.emplace_back(BlueprintFieldType::value_type::zero());
                    return next_free_lc++;
                }
            };
        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_BLUEPRINT_R1CS_HPP
