//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2023 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022-2023 Polina Chernyshova <pockvokhbtra@nil.foundation>
// Copyright (c) 2022-2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of PLONK table profiling util.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP
#define CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace blueprint {
        template<typename ValueType>
        void profiling(std::vector<ValueType> column, std::ostream &out = std::cout) {
            for (std::size_t index = 0; index < column.size(); index++) {
                out << "\t" << column[index].data;
            }
        }

        template<typename FieldType, typename ArithmetizationParams>
        void profiling(const crypto3::zk::snark::plonk_assignment_table<FieldType, ArithmetizationParams>& assignments, std::ostream &out = std::cout) {

            for (std::size_t row_index = 0; row_index < assignments.rows_amount(); row_index++) {
                out << "\t" << row_index;
            }
            out << std::endl;

            for (std::size_t w_index = 0; w_index < ArithmetizationParams::witness_columns; w_index++) {
                out << "W" << w_index << ":";
                profiling(assignments.witness(w_index), out);
                out << std::endl;
            }

            for (std::size_t pi_index = 0; pi_index < ArithmetizationParams::public_input_columns; pi_index++) {
                std::cout << "PI" << pi_index << ":";
                profiling(assignments.public_input(pi_index), out);
                out << std::endl;
            }

            for (std::size_t c_index = 0; c_index < ArithmetizationParams::constant_columns; c_index++) {
                out << "C" << c_index << ":";
                profiling(assignments.constant(c_index), out);
                out << std::endl;
            }

            for (std::size_t s_index = 0; s_index < ArithmetizationParams::selector_columns; s_index++) {
                out << "S" << s_index << ":";
                profiling(assignments.selector(s_index), out);
                out << std::endl;
            }
        }


        template<typename FieldType, typename ArithmetizationParams>
        void profiling_assignment_table(
            const crypto3::zk::snark::plonk_assignment_table<FieldType, ArithmetizationParams>& assignments,
            std::size_t usable_rows, 
            std::ostream &out = std::cout
        ) {
            out << usable_rows << std::endl;
            out << assignments.rows_amount() << std::endl;

            for (std::size_t w_index = 0; w_index < ArithmetizationParams::witness_columns; w_index++) {
                profiling(assignments.witness(w_index), out);
                out << std::endl;
            }

            for (std::size_t pi_index = 0; pi_index < ArithmetizationParams::public_input_columns; pi_index++) {
                profiling(assignments.public_input(pi_index), out);
                out << std::endl;
            }

            for (std::size_t c_index = 0; c_index < ArithmetizationParams::constant_columns; c_index++) {
                profiling(assignments.constant(c_index), out);
                out << std::endl;
            }

            for (std::size_t s_index = 0; s_index < ArithmetizationParams::selector_columns; s_index++) {
                profiling(assignments.selector(s_index), out);
                out << std::endl;
            }
        }

        template<typename BlueprintFieldType, typename ArithmetizationParams, typename ColumnType>
        std::tuple<std::size_t, std::size_t,
                nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>>
            load_assignment_table(std::istream &istr) {
            using PrivateTableType =
                nil::crypto3::zk::snark::plonk_private_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
            using PublicTableType =
                nil::crypto3::zk::snark::plonk_public_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
            using AssignmentTableType =
                nil::crypto3::zk::snark::plonk_table<BlueprintFieldType, ArithmetizationParams, ColumnType>;
            std::size_t usable_rows;
            std::size_t rows_amount;

            typename PrivateTableType::witnesses_container_type witness;
            typename PublicTableType::public_input_container_type public_input;
            typename PublicTableType::constant_container_type constant;
            typename PublicTableType::selector_container_type selector;

            istr >> usable_rows;
            istr >> rows_amount;

            for (size_t i = 0; i < witness.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
                ColumnType column;
                typename BlueprintFieldType::integral_type num;
                for (size_t j = 0; j < rows_amount; j++) {
                    istr >> num;
                    column.push_back(typename BlueprintFieldType::value_type(num));
                }
                witness[i] = column;
            }

            for (size_t i = 0; i < public_input.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
                ColumnType column;
                typename BlueprintFieldType::integral_type num;
                for (size_t j = 0; j < rows_amount; j++) {
                    istr >> num;
                    column.push_back(typename BlueprintFieldType::value_type(num));
                }
                public_input[i] = column;
            }

            for (size_t i = 0; i < constant.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
                ColumnType column;
                typename BlueprintFieldType::integral_type num;
                for (size_t j = 0; j < rows_amount; j++) {
                    istr >> num;
                    column.push_back(typename BlueprintFieldType::value_type(num));
                }
                constant[i] = column;
            }
            for (size_t i = 0; i < selector.size(); i++) {    // witnesses.size() == ArithmetizationParams.WitnessColumns
                ColumnType column;
                typename BlueprintFieldType::integral_type num;
                for (size_t j = 0; j < rows_amount; j++) {
                    istr >> num;
                    column.push_back(typename BlueprintFieldType::value_type(num));
                }
                selector[i] = column;
            }
            return std::make_tuple(
                usable_rows, rows_amount,
                AssignmentTableType(PrivateTableType(witness), PublicTableType(public_input, constant, selector)));
        }

    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_TABLE_PROFILING_HPP
