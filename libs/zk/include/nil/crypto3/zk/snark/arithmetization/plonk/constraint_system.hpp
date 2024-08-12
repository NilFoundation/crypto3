//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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
// @file Declaration of interfaces for:
//
// - a PLONK gate,
// - a PLONK variable assignment, and
// - a PLONK constraint system.
//
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_PLONK_CONSTRAINT_SYSTEM_HPP
#define CRYPTO3_ZK_PLONK_CONSTRAINT_SYSTEM_HPP

#include <cstdlib>
#include <vector>
#include <set>

#include <nil/crypto3/zk/snark/arithmetization/plonk/gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_gate.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_table.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /************************* PLONK constraint system ****************************/

                template<typename FieldType>
                struct plonk_constraint_system {
                    typedef std::vector<plonk_gate<FieldType, plonk_constraint<FieldType>>> gates_container_type;
                    typedef plonk_variable<typename FieldType::value_type> variable_type;
                    typedef std::vector<plonk_copy_constraint<FieldType>> copy_constraints_container_type;
                    typedef std::vector<plonk_lookup_gate<FieldType, plonk_lookup_constraint<FieldType>>> lookup_gates_container_type;
                    typedef plonk_lookup_table<FieldType> lookup_table_type;
                    typedef std::vector<lookup_table_type> lookup_tables_type;
                    typedef std::vector<plonk_variable<typename FieldType::value_type>> public_input_gate_type;
                    typedef math::expression_max_degree_visitor<variable_type> degree_visitor_type;
                    typedef math::expression<variable_type> expression_type;
                    typedef math::term<variable_type> term_type;
                    typedef math::binary_arithmetic_operation<variable_type> binary_operation_type;
                    typedef math::pow_operation<variable_type> pow_operation_type;
                    typedef std::vector<std::size_t> public_input_sizes_type;
                    typedef FieldType field_type;

                protected:
                    gates_container_type _gates;
                    copy_constraints_container_type _copy_constraints;
                    lookup_gates_container_type _lookup_gates;
                    lookup_tables_type _lookup_tables;
                    // If empty, then check full column
                    public_input_sizes_type _public_input_sizes;
                public:

                    plonk_constraint_system() {
                    }

                    virtual ~plonk_constraint_system() = default;

                    plonk_constraint_system(const gates_container_type &gates,
                                            const copy_constraints_container_type &copy_constraints,
                                            const lookup_gates_container_type &lookup_gates = {},
                                            const lookup_tables_type &lookup_tables = {},
                                            const public_input_sizes_type &public_input_sizes = {}
                    ) :
                        _gates(gates),
                        _copy_constraints(copy_constraints),
                        _lookup_gates(lookup_gates),
                        _lookup_tables(lookup_tables),
                        _public_input_sizes(public_input_sizes)
                    {
                    }

                    // Use std::set to ensure elements in permuted_columns are iterated in ascending order.
                    std::set<variable_type> permuted_columns() const{
                        std::set<variable_type> result;
                        for( std::size_t i = 0; i < _copy_constraints.size(); i++){
                            auto var0 = _copy_constraints[i].first;
                            auto var1 = _copy_constraints[i].second;
                            result.insert(variable_type(var0.index, 0, true, var0.type));
                            result.insert(variable_type(var1.index, 0, true, var1.type));
                        }
                        return std::move(result);
                    }

                    std::size_t public_input_total_size() const {
                        return std::accumulate(_public_input_sizes.begin(), _public_input_sizes.end(), 0);
                    }

                    std::size_t public_input_size(std::size_t i) const {
                        assert(i < _public_input_sizes.size());
                        return _public_input_sizes[i];
                    }

                    std::size_t public_input_sizes_num() const {
                        return _public_input_sizes.size();
                    }

                    const std::vector<std::size_t> &public_input_sizes() const{
                        return _public_input_sizes;
                    }

                    std::size_t num_gates() const {
                        return _gates.size();
                    }

                    std::size_t num_lookup_gates() const {
                        return _lookup_gates.size();
                    }

                    const gates_container_type &gates() const {
                        return _gates;
                    }

                    const copy_constraints_container_type &copy_constraints() const {
                        return _copy_constraints;
                    }

                    copy_constraints_container_type &mutable_copy_constraints() {
                        return _copy_constraints;
                    }

                    const lookup_gates_container_type &lookup_gates() const {
                        return _lookup_gates;
                    }

                    const lookup_tables_type &lookup_tables() const {
                        return _lookup_tables;
                    }

                    const lookup_table_type &lookup_table(std::size_t table_id) const {
                        return _lookup_tables[table_id];
                    }

                    void add_lookup_table(const lookup_table_type &table) {
                        _lookup_tables.push_back(table);
                    }

                    std::size_t sorted_lookup_columns_number() const {
                        if(_lookup_gates.size() == 0){
                            return 0;
                        }
                        return lookup_options_num() + lookup_constraints_num();
                    }

                    std::size_t lookup_options_num() const {
                        std::size_t result = 0;
                        for(std::size_t i = 0; i < _lookup_tables.size(); ++i) {
                            result += _lookup_tables[i].lookup_options.size();
                        }
                        return result;
                    }

                    std::size_t lookup_constraints_num() const{
                        std::size_t result = 0;
                        for(std::size_t i = 0; i < _lookup_gates.size(); ++i) {
                            result += _lookup_gates[i].constraints.size();
                        }
                        return result;
                    }

                    std::size_t lookup_expressions_num() const{
                        std::size_t result = 0;
                        for(std::size_t i = 0; i < _lookup_gates.size(); ++i) {
                            for(std::size_t j = 0; j < _lookup_gates[i].constraints.size(); ++j) {
                                result += _lookup_gates[i].constraints[j].lookup_input.size();
                            }
                        }
                        return result;
                    }

                    std::size_t lookup_tables_columns_num() const{
                        std::size_t result = 0;
                        for(std::size_t i = 0; i < _lookup_tables.size(); ++i) {
                            result += _lookup_tables[i].lookup_options[0].size() * _lookup_tables[i].lookup_options.size();
                        }
                        return result;
                    }

                    std::size_t max_gates_degree() const {
                        std::size_t max_gates_degree = 0;
                        math::expression_max_degree_visitor<variable_type> gates_visitor;
                        for (const auto& gate : _gates) {
                            for (const auto& constr : gate.constraints) {
                                std::size_t deg = gates_visitor.compute_max_degree(constr);
                                max_gates_degree = std::max(max_gates_degree, deg);
                            }
                        }
                        return max_gates_degree;
                    }

                    std::size_t max_lookup_gates_degree() const {
                        std::size_t max_lookup_gates_degree = 0;
                        math::expression_max_degree_visitor<variable_type> lookup_visitor;
                        for (const auto& gate :_lookup_gates) {
                            for (const auto& constr : gate.constraints) {
                                for (const auto& li : constr.lookup_input) {
                                    std::size_t deg = lookup_visitor.compute_max_degree(li);
                                    max_lookup_gates_degree = std::max(
                                        max_lookup_gates_degree,
                                        deg
                                    );
                                }
                            }
                        }
                        return max_lookup_gates_degree;
                    }

                    std::size_t lookup_poly_degree_bound() const{
                        std::uint32_t lookup_degree = 0;
                        if(_lookup_gates.size() > 0){
                            degree_visitor_type degree_visitor;
                            for(std::size_t i = 0; i < _lookup_gates.size(); i++){
                                for(std::size_t j = 0; j < _lookup_gates[i].constraints.size(); j++){
                                    std::size_t degree = 0;
                                    for(std::size_t k = 0; k < _lookup_gates[i].constraints[j].lookup_input.size(); k++){
                                        degree = std::max(degree, std::size_t(degree_visitor.compute_max_degree(_lookup_gates[i].constraints[j].lookup_input[k])));
                                    }
                                    lookup_degree += (degree + 1);
                                }
                            }
                            for(std::size_t i = 0; i < _lookup_tables.size(); i++){
                                lookup_degree += 3 * _lookup_tables[i].lookup_options.size();
                            }
                        }
                        return lookup_degree;
                    }


                    std::vector<std::size_t> lookup_parts(
                        std::size_t max_quotient_chunks
                    ) const {
                        if( max_quotient_chunks == 0 ){
                            return {this->sorted_lookup_columns_number()};
                        }

                        using VariableType = plonk_variable<typename FieldType::value_type>;
                        typedef math::expression_max_degree_visitor<VariableType> degree_visitor_type;
                        std::vector<std::size_t> lookup_parts;
                        degree_visitor_type lookup_visitor;

                        std::size_t lookup_chunk = 0;
                        std::size_t lookup_part = 0;
                        std::size_t max_constraint_degree;
                        for (const auto& gate :_lookup_gates) {
                            for (const auto& constr : gate.constraints) {
                                max_constraint_degree = 0;
                                for (const auto& li : constr.lookup_input) {
                                    std::size_t deg = lookup_visitor.compute_max_degree(li);
                                    max_constraint_degree = std::max(
                                        max_constraint_degree,
                                        deg
                                    );
                                }
                                if( lookup_chunk + max_constraint_degree + 1>= max_quotient_chunks ){
                                    lookup_parts.push_back(lookup_part);
                                    lookup_chunk = 0;
                                    lookup_part = 0;
                                }
                                // +1 because lookup input is multiplied by selector
                                lookup_chunk += max_constraint_degree + 1;
                                lookup_part++;
                            }
                        }
                        for (const auto& table : _lookup_tables) {
                            for (std::size_t i = 0; i < table.lookup_options.size(); ++i) {
                                // +3 because now any lookup option is lookup_column * lookup_selector * (1-q_last-q_blind) -- three polynomials degree rows_amount-1
                                if( lookup_chunk + 3 >= max_quotient_chunks ){
                                    lookup_parts.push_back(lookup_part);
                                    lookup_chunk = 0;
                                    lookup_part = 0;
                                }
                                lookup_chunk += 3;
                                lookup_part++;
                            }
                        }

                        lookup_parts.push_back(lookup_part);
                        return lookup_parts;
                    }

                    bool operator==(const plonk_constraint_system<FieldType> &other) const {
                        return (this->_gates == other._gates) && (this->_copy_constraints == other._copy_constraints) &&
                               (this->_lookup_gates == other._lookup_gates) && (this->_lookup_tables == other._lookup_tables) &&
                               (this->_public_input_sizes == other._public_input_sizes);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_CONSTRAINT_SYSTEM_HPP
