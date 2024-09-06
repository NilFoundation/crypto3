//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for PLONK BBF context & generic component classes
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP
#define CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP

#include <functional>

#include <boost/log/trivial.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
// #include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp> // NB: part of the previous include

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
//#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/gate_id.hpp>

#include <nil/blueprint/bbf/bool_field.hpp>

namespace nil {
    namespace blueprint {
        namespace bbf {

            enum class GenerationStage { ASSIGNMENT = 0, CIRCUIT = 1 };

            enum column_type { witness, public_input, constant, COLUMN_TYPES };

            std::ostream &operator<<(std::ostream &os, const column_type &t) {
                std::map<column_type, std::string> type_map = {
                    {column_type::witness, "witness"},
                    {column_type::public_input, "public input"},
                    {column_type::constant, "constant"},
                    {column_type::COLUMN_TYPES, " "}
                };
                os << type_map[t];
                return os;
            }

            template<typename FieldType>
            class basic_context {
                using bool_field = crypto3::algebra::fields::bool_field;
                using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;
                using allocation_log_type = assignment<crypto3::zk::snark::plonk_constraint_system<bool_field>>;

                private:
                    allocation_log_type al;
                    std::size_t current_row[COLUMN_TYPES];

                public:
                    bool is_allocated(std::size_t col, std::size_t row, column_type t) {
                        bool_field::value_type cell;
                        switch (t) {
                            case column_type::witness:
                                 cell = al.witness(col,row);
                                 break;
                            case column_type::public_input:
                                 cell = al.public_input(col,row);
                                 break;
                            case column_type::constant:
                                 cell = al.constant(col,row);
                                 break;
                        }
                        return (cell == bool_field::value_type::one());
                    }

                    void mark_allocated(std::size_t col, std::size_t row, column_type t) {
                        switch (t) {
                            case column_type::witness:
                                 al.witness(col,row) = 1;
                                 break;
                            case column_type::public_input:
                                 al.public_input(col,row) = 1;
                                 break;
                            case column_type::constant:
                                 al.constant(col,row) = 1;
                                 break;
                        }
                    }

                    std::size_t columns_amount(column_type t) {
                        switch (t) {
                            case column_type::witness:
                                 return al.witnesses_amount();
                                 break;
                            case column_type::public_input:
                                 return al.public_inputs_amount();
                                 break;
                            case column_type::constant:
                                 return al.constants_amount();
                                 break;
                        }
                        return 0;
                    }

                    std::pair<std::size_t, std::size_t> next_free_cell(column_type t) {
                        std::size_t col = 0, row = 0, hsize = 0;
                        bool found = false;

                        hsize = columns_amount(t);

                        row = current_row[t];
                        col = 0;

                        while(!found) { // TODO: number of rows can be exceeded?
                            if (col > hsize) {
                                current_row[t]++;
                                row = current_row[t];
                                col = 0;
                            }

                            found = !is_allocated(col,row,t);

                            if (!found) {
                                col++;
                            }
                        }

                        return {col, row};
                    }

                    basic_context(assignment_type &at) :
                        al(at.witnesses_amount(), at.public_inputs_amount(), at.constants_amount(), at.selectors_amount()),
                        current_row{0, 0, 0} // For all types of columns start from 0. TODO: this might not be a good idea
                    { };
            };

            template<typename FieldType, GenerationStage stage> class context;

            template<typename FieldType>
            class context<FieldType, GenerationStage::ASSIGNMENT> : public basic_context<FieldType> { // assignment-specific definition
                using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;
                public:
                    using TYPE = typename FieldType::value_type;
                    using basic_context<FieldType>::is_allocated;
                    using basic_context<FieldType>::mark_allocated;

                private:
                    // reference to actual assignment table
                    assignment_type &at;

                public:
                    void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                        if (is_allocated(col, row, t)) {
                            BOOST_LOG_TRIVIAL(warning) << "Cell of " << t << " RE-allocation at col = " << col << ", row = " << row << ".";
                        }
                        switch (t) {
                            case column_type::witness:      at.witness(col, row) = C;      break;
                            case column_type::public_input: at.public_input(col, row) = C; break;
                            case column_type::constant:     at.constant(col, row) = C;     break;
                        }
                        mark_allocated(col,row,t);
                    }

                    context(assignment_type &assignment_table) : basic_context<FieldType>(assignment_table), at(assignment_table) { };
            };

            template<typename FieldType>
            class context<FieldType, GenerationStage::CIRCUIT> : public basic_context<FieldType> { // circuit-specific definition
                using constraint_id_type = gate_id<FieldType>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using copy_constraints_container_type = std::vector<plonk_copy_constraint>; // TODO: maybe it's a set, not a vec?

                using TYPE = constraint_type;
                using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;

                private:
                    // constraints (with unique id), and the rows they are applied to
                    std::map<constraint_id_type, std::pair<constraint_type, std::vector<std::size_t>>> constraints;
                    copy_constraints_container_type copy_constraints;

                public:
                    void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                    }

                    context(assignment_type &at) : basic_context<FieldType>(at) { };
            };



            template<typename FieldType, GenerationStage stage>
            class generic_component {
                public:
                    using TYPE = typename std::conditional<static_cast<bool>(stage),
                                 crypto3::zk::snark::plonk_constraint<FieldType>,
                                 typename FieldType::value_type>::type;
                    using context_type = context<FieldType, stage>;

                private:
                    context_type &ct;

                public:
                    void allocate(TYPE &C, column_type t = column_type::witness) {
                        auto [col, row] = ct.next_free_cell(t);
                        ct.allocate(C,col,row,t);
                    }

                    void allocate(TYPE &C, size_t col, size_t row, column_type t = column_type::witness) {
                        ct.allocate(C,col,row,t);
                    }

                    generic_component(context_type &context_object, // context object, created outside
                                      bool crlf = true              // do we assure a component starts on a new row? Default is "yes"
                                     ) : ct(context_object) {
                        // TODO: Implement crlf parameter consequences
                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP
