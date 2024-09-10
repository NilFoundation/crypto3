//---------------------------------------------------------------------------//
// Copyright (c) 2024 Dmitrii Tabalin <d.tabalin@nil.foundation>
// Copyright (c) 2024 Alexey Yashunsky <a.yashunsky@nil.foundation>
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

#pragma once

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/variable.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <ostream>

namespace nil {
    namespace blueprint {

        // we use value_type as a default here in order to have easier time testing weird assignments like -1
        template<typename BlueprintFieldType, typename T = typename BlueprintFieldType::value_type>
        struct state_var {
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using column_type = typename var::column_type;

            std::size_t selector;
            column_type type;
            T value;

            state_var(const std::size_t selector_, const column_type type_, const T& value_)
                : selector(selector_), type(type_), value(value_) {}

            state_var() = default;

            void set_value(const T &new_value) {
                value = new_value;
            }

            void assign_value(assignment_type &assignment, std::size_t row) const {
                switch (type) {
                    case column_type::witness:
                        assignment.witness(selector, row) = value;
                        break;
                    case column_type::constant:
                        assignment.constant(selector, row) = value;
                        break;
                    case column_type::selector:
                        assignment.selector(selector, row) = value;
                        break;
                    case column_type::public_input:
                        BOOST_ASSERT("We should not assign a state value to public input column");
                    default:
                        BOOST_ASSERT("Unknown column type");
                }
            }

            void set_and_assign_value(assignment_type &assignment, std::size_t row, const T &new_value) {
                set_value(new_value);
                assign_value(assignment, row);
            }

            var variable(int32_t offset = 0) const {
                BOOST_ASSERT(offset == 0 || offset == -1 || offset == 1);
                return var(selector, offset, true, type);
            }
        };

        #define zkevm_STATE_LIST_FOR_TRANSITIONS(X) \
            X(pc) \
            X(stack_size) \
            X(memory_size) \
            X(curr_gas) \

        // Every variable which should be tracked between rows
        template<typename BlueprintFieldType>
        struct zkevm_state {
            using state_var_type = state_var<BlueprintFieldType>;
            using arithmetization_type = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>;
            using assignment_type = nil::blueprint::assignment<arithmetization_type>;
            // variables which have custom state transitions
            #define X(name) state_var_type name;
            zkevm_STATE_LIST_FOR_TRANSITIONS(X)
            #undef X
            // variables which have generic transition rules and are not handled via
            // state transition mechanism
            state_var_type step_selection; // 1 in first line of new opcode, 0 otherwise
            state_var_type rows_until_next_op_inv;
            state_var_type last_row_indicator;

            void assign_state(assignment_type &assignment, std::size_t row) const {
                #define X(name) name.assign_value(assignment, row);
                zkevm_STATE_LIST_FOR_TRANSITIONS(X)
                #undef X
                step_selection.assign_value(assignment, row);
                rows_until_next_op_inv.assign_value(assignment, row);
                last_row_indicator.assign_value(assignment, row);
            }
        };

        struct transition_type {
            enum type {
                DEFAULT,
                ANY,
                SAME_VALUE,
                DELTA,
                NEW_VALUE,
            };
            transition_type()
                :t(DEFAULT),
                 value(0){}

            type t;
            // either new value or delta; optional
            // technically we could do arbirary field values here, but unlikely to be actually required
            std::int64_t value;
        };

        std::ostream& operator<<(std::ostream &os, const transition_type &t) {
            switch (t.t) {
                case transition_type::DEFAULT:
                    os << "DEFAULT";
                    break;
                case transition_type::ANY:
                    os << "ANY";
                    break;
                case transition_type::SAME_VALUE:
                    os << "SAME_VALUE";
                    break;
                case transition_type::DELTA:
                    os << "DELTA(" << t.value << ")";
                    break;
                case transition_type::NEW_VALUE:
                    os << "NEW_VALUE(" << t.value << ")";
                    break;
            }
            return os;
        }

        struct zkevm_state_transition {
            #define X(name) transition_type name;
            zkevm_STATE_LIST_FOR_TRANSITIONS(X)
            #undef X
        };

        zkevm_state_transition generate_frozen_state_transition() {
            zkevm_state_transition transition;
            #define X(name) transition.name.t = transition_type::SAME_VALUE;
            zkevm_STATE_LIST_FOR_TRANSITIONS(X)
            #undef X
            return transition;
        }

        std::ostream& operator<<(std::ostream &os, const zkevm_state_transition &t) {
            #define X(name) os << #name << ": " << t.name << std::endl;
            zkevm_STATE_LIST_FOR_TRANSITIONS(X)
            #undef X
            return os;
        }

        template<typename BlueprintFieldType>
        std::optional<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> handle_transition(
            const state_var<BlueprintFieldType> &var,
            const transition_type &transition,
            std::function<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>(
                const state_var<BlueprintFieldType>&, const transition_type&)> default_handler
        ) {
            switch (transition.t) {
                case transition_type::SAME_VALUE:
                    return var.variable(+1) - var.variable();
                case transition_type::DELTA:
                    return var.variable(+1) - var.variable() - transition.value;
                case transition_type::NEW_VALUE:
                    return var.variable(+1) - transition.value;
                case transition_type::DEFAULT:
                    return default_handler(var, transition);
                case transition_type::ANY:
                    return std::nullopt;
            }
        }

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_constraint<BlueprintFieldType> handle_pc_default(
            const state_var<BlueprintFieldType> &var,
            const transition_type &transition
        ) {
            // same as DELTA(1)
            return var.variable(+1) - var.variable() - 1;
        }

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_constraint<BlueprintFieldType> handle_stack_size_default(
            const state_var<BlueprintFieldType> &var,
            const transition_type &transition
        ) {
            // same as SAME
            return var.variable(+1) - var.variable();
        }

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_constraint<BlueprintFieldType> handle_memory_size_default(
            const state_var<BlueprintFieldType> &var,
            const transition_type &transition
        ) {
            // same as SAME
            return var.variable(+1) - var.variable();
        }

        template<typename BlueprintFieldType>
        crypto3::zk::snark::plonk_constraint<BlueprintFieldType> handle_curr_gas_default(
            const state_var<BlueprintFieldType> &var,
            const transition_type &transition
        ) {
            // we shouldn't do this? maybe in error cases or testing?
            // later should assert this out, currently SAME
            return var.variable(+1) - var.variable();
        }

        template<typename BlueprintFieldType>
        std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> generate_transition_constraints(
            const zkevm_state<BlueprintFieldType> &state,
            const zkevm_state_transition &transition
        ) {
            using constraint_type = crypto3::zk::snark::plonk_constraint<BlueprintFieldType>;
            std::vector<constraint_type> result;
            #define X(name) \
                if (auto constraint = handle_transition<BlueprintFieldType>( \
                        state.name, transition.name, handle_##name##_default<BlueprintFieldType>)) { \
                    result.push_back(*constraint); \
                }
            zkevm_STATE_LIST_FOR_TRANSITIONS(X)
            #undef X
            return result;
        }
    }    // namespace blueprint
}    // namespace nil
