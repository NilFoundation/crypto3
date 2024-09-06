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
// #include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp> // NB: part of the privious include

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

            template<typename FieldType, GenerationStage stage> class context {
                using bool_field = crypto3::algebra::fields::bool_field;
                using allocation_log_type = assignment<crypto3::zk::snark::plonk_constraint_system<bool_field>>;

                private:
                    allocation_log_type al;

                public:
                    std::size_t current_row[COLUMN_TYPES];
                    std::pair<std::size_t, std::size_t> next_free_cell(column_type t);
            };

            template<typename FieldType>
            class context<FieldType, GenerationStage::ASSIGNMENT> { // assignment-specific definition
                using bool_field = crypto3::algebra::fields::bool_field;

                using TYPE = typename FieldType::value_type;
                using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;
                using allocation_log_type = assignment<crypto3::zk::snark::plonk_constraint_system<bool_field>>;

                private:
                    // reference to actual assignment table
                    assignment_type &at;
                    // to track the allocation process
                    allocation_log_type al;


                public:
                    std::size_t current_row[COLUMN_TYPES];

                    std::pair<std::size_t, std::size_t> next_free_cell(column_type t);

                    void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                        switch (t) {
                            case column_type::witness:
                                if (al.witness(col,row) == 1) {
                                    BOOST_LOG_TRIVIAL(warning) << "Witness RE-allocation at col = " << col << ", row = " << row << ".";
                                }
                                at.witness(col, row) = C;
                                al.witness(col, row) = 1;
                                break;
                            case column_type::public_input:
                                if (al.public_input(col,row) == 1) {
                                    BOOST_LOG_TRIVIAL(warning) << "Public input RE-allocation at col = " << col << ", row = " << row << ".";
                                }
                                at.public_input(col, row) = C;
                                al.public_input(col, row) = 1;
                                break;
                            case column_type::constant:
                                if (al.constant(col,row) == 1) {
                                    BOOST_LOG_TRIVIAL(warning) << "Constant RE-allocation at col = " << col << ", row = " << row << ".";
                                }
                                at.constant(col, row) = C;
                                al.constant(col, row) = 1;
                                break;
                        }
                    }

                    context(assignment_type &assignment_table) :
                        at(assignment_table),
                        al(at.witnesses_amount(), at.public_inputs_amount(), at.constants_amount(), at.selectors_amount()),
                        current_row{0, 0, 0} // For all types of columns start from 0. TODO: this might not be a good idea
                    {
                    };
            };

            template<typename FieldType>
            class context<FieldType, GenerationStage::CIRCUIT> { // circuit-specific definition
                using bool_field = crypto3::algebra::fields::bool_field;
                using constraint_id_type = gate_id<FieldType>;
                using constraint_type = crypto3::zk::snark::plonk_constraint<FieldType>;
                using plonk_copy_constraint = crypto3::zk::snark::plonk_copy_constraint<FieldType>;
                using copy_constraints_container_type = std::vector<plonk_copy_constraint>; // TODO: maybe it's a set, not a vec?

                using TYPE = constraint_type;
                using assignment_type = assignment<crypto3::zk::snark::plonk_constraint_system<FieldType>>;
                using allocation_log_type = assignment<crypto3::zk::snark::plonk_constraint_system<bool_field>>;

                private:
                    // to track the allocation process
                    allocation_log_type al;

                    // constraints (with unique id), and the rows they are applied to
                    std::map<constraint_id_type, std::pair<constraint_type, std::vector<std::size_t>>> constraints;
                    copy_constraints_container_type copy_constraints;

                public:
                    std::size_t current_row[COLUMN_TYPES];

                    std::pair<std::size_t, std::size_t> next_free_cell(column_type t);

                    void allocate(TYPE &C, size_t col, size_t row, column_type t) {
                    }

                    context(assignment_type &at) :
                        al(at.witnesses_amount(), at.public_inputs_amount(), at.constants_amount(), at.selectors_amount()),
                        current_row{0, 0, 0} // For all types of columns start from 0. TODO: this might not be a good idea
                    {
                    };
            };

            template<typename FieldType, GenerationStage stage>
            std::pair<std::size_t, std::size_t> context<FieldType,stage>::next_free_cell(column_type t) {
                std::size_t col = 0, row = 0, hsize = 0;
                bool found = false;

                std::cout << "In NFC func\n";
/*
                switch (t) {
                    case column_type::witness:
                         hsize = al.witnesses_amount();
                         break;
                    case column_type::public_input:
                         hsize = al.public_inputs_amount();
                         break;
                    case column_type::constant:
                         hsize = al.constants_amount();
                         break;
                    }

                row = current_row[t];
                col = 0;

                std::cout << "hsize = " << hsize << "\n";

                while(!found) {
                    if (col > hsize) {
                        current_row[t]++;
                        row = current_row[t];
                        col = 0;
                    }
                    switch (t) {
                        case column_type::witness:
                             found = (al.witness(col,row) == 0);
                             break;
                        case column_type::public_input:
                             found = (al.public_input(col,row) == 0);
                             break;
                        case column_type::constant:
                             found = (al.constant(col,row) == 0);
                             break;
                    }
                    if (!found) {
                        col++;
                    }
                }
*/
                return {col, row};
            }

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
                        std::cout << "NFC col = " << col << ", row = " << row << "\n";
                        ct.allocate(C,col,row,t);
                    }

                    void allocate(TYPE &C, size_t col, size_t row, column_type t = column_type::witness) {
                        ct.allocate(C,col,row,t);
                    }

                    generic_component(context_type &context_object, // context object, created outside
                                      bool crlf = true              // do we assure a component starts on a new row? Default is "yes"
                                     ) : ct(context_object) {

                    };
            };

        } // namespace bbf
    } // namespace blueprint
} // namespace nil

#endif // CRYPTO3_BLUEPRINT_PLONK_BBF_GENERIC_HPP
