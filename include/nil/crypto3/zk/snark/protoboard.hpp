//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PROTOBOARD_HPP_
#define CRYPTO3_ZK_PROTOBOARD_HPP_

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#include <nil/crypto3/zk/snark/pb_variable.hpp>
#include <nil/crypto3/zk/snark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                template<typename FieldType>
                class r1cs_constraint;

                template<typename FieldType>
                class r1cs_constraint_system;

                template<typename FieldType>
                class protoboard {
                    r1cs_variable_assignment<FieldType> values; /* values[0] will hold the value of the first allocated
                                                                variable of the protoboard, *NOT* constant 1 */
                    var_index_t next_free_var;
                    lc_index_t next_free_lc;
                    std::vector<typename FieldType::value_type> lc_values;
                    r1cs_constraint_system<FieldType> constraint_system;

                public:
                    typedef FieldType field_type;

                    protoboard() {
                        next_free_var = 1; /* to account for constant 1 term */
                        next_free_lc = 0;
                    }

                    void clear_values() {
                        std::fill(values.begin(), values.end(), FieldType::zero());
                    }

                    FieldType &val(const pb_variable<FieldType> &var) {
                        assert(var.index <= values.size());
                        return (var.index == 0 ? FieldType::one() : values[var.index - 1]);
                    }

                    FieldType val(const pb_variable<FieldType> &var) const {
                        assert(var.index <= values.size());
                        return (var.index == 0 ? FieldType::one() : values[var.index - 1]);
                    }

                    FieldType &lc_val(const pb_linear_combination<FieldType> &lc) {
                        if (lc.is_variable) {
                            return this->val(pb_variable<FieldType>(lc.index));
                        } else {
                            assert(lc.index < lc_values.size());
                            return lc_values[lc.index];
                        }
                    }

                    FieldType lc_val(const pb_linear_combination<FieldType> &lc) const {
                        if (lc.is_variable) {
                            return this->val(pb_variable<FieldType>(lc.index));
                        } else {
                            assert(lc.index < lc_values.size());
                            return lc_values[lc.index];
                        }
                    }

                    void add_r1cs_constraint(const r1cs_constraint<FieldType> &constr) {
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

                    r1cs_variable_assignment<FieldType> full_variable_assignment() const {
                        return values;
                    }

                    r1cs_primary_input<FieldType> primary_input() const {
                        return r1cs_primary_input<FieldType>(values.begin(), values.begin() + num_inputs());
                    }

                    r1cs_auxiliary_input<FieldType> auxiliary_input() const {
                        return r1cs_auxiliary_input<FieldType>(values.begin() + num_inputs(), values.end());
                    }

                    r1cs_constraint_system<FieldType> get_constraint_system() const {
                        return constraint_system;
                    }

                    friend class pb_variable<FieldType>;
                    friend class pb_linear_combination<FieldType>;

                private:
                    var_index_t allocate_var_index() {
                        ++constraint_system.auxiliary_input_size;
                        values.emplace_back(FieldType::zero());
                        return next_free_var++;
                    }

                    lc_index_t allocate_lc_index() {
                        lc_values.emplace_back(FieldType::zero());
                        return next_free_lc++;
                    }
                };

            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil
#endif    // PROTOBOARD_HPP_
