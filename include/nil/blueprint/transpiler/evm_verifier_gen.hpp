//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//
#ifndef __EVM_VERIFIER_GEN_HPP__
#define __EVM_VERIFIER_GEN_HPP__

#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <unordered_set>

#include <boost/algorithm/string.hpp>
#include <nil/blueprint/transpiler/templates/modular_verifier.hpp>
#include <nil/blueprint/transpiler/templates/gate_argument.hpp>
#include <nil/blueprint/transpiler/templates/permutation_argument.hpp>
#include <nil/blueprint/transpiler/templates/lookup_argument.hpp>
#include <nil/blueprint/transpiler/templates/commitment_scheme.hpp>
#include <nil/blueprint/transpiler/templates/external_gate.hpp>
#include <nil/blueprint/transpiler/templates/external_lookup.hpp>
#include <nil/blueprint/transpiler/templates/utils_template.hpp>
#include <nil/blueprint/transpiler/lpc_scheme_gen.hpp>
#include <nil/blueprint/transpiler/util.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/detail/digest.hpp>

namespace nil {
    namespace blueprint {
        template <typename PlaceholderParams>
        class evm_verifier_printer{
            using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<
                typename PlaceholderParams::field_type,
                PlaceholderParams
            >::preprocessed_data_type::common_data_type;

            using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
            using constraint_type = nil::crypto3::zk::snark::plonk_constraint<typename PlaceholderParams::field_type>;
            using lookup_constraint_type = nil::crypto3::zk::snark::plonk_lookup_constraint<typename PlaceholderParams::field_type>;
            using gate_type = nil::crypto3::zk::snark::plonk_gate<typename PlaceholderParams::field_type, constraint_type>;
            using lookup_gate_type = nil::crypto3::zk::snark::plonk_lookup_gate<typename PlaceholderParams::field_type, lookup_constraint_type>;
            using variable_indices_type = std::map<nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>, std::size_t>;
            using columns_rotations_type = std::array<std::set<int>, PlaceholderParams::total_columns>;

            variable_indices_type get_plonk_variable_indices(const columns_rotations_type &col_rotations){
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
                std::map<variable_type, std::size_t> result;
                std::size_t j = 0;
                for(std::size_t i = 0; i < PlaceholderParams::constant_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::constant);
                        result[v] = j;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::selector_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns + PlaceholderParams::constant_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::selector);
                        result[v] = j;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::witness_columns; i++){
                    for(auto& rot: col_rotations[i]){
                        variable_type v(i, rot, true, variable_type::column_type::witness);
                        result[v] = j;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < PlaceholderParams::public_input_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::public_input);
                        result[v] = j;
                        j++;
                    }
                }
                return result;
            }

            std::string zero_indices(columns_rotations_type col_rotations){
                std::vector<std::size_t> zero_indices;
                std::uint16_t fixed_values_points = 0;
                std::stringstream result;

                for(std::size_t i= 0; i < PlaceholderParams::constant_columns + PlaceholderParams::selector_columns; i++){
                    fixed_values_points += col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns].size() + 1;
                }

                for(std::size_t i= 0; i < PlaceholderParams::total_columns; i++){
                    std::size_t j = 0;
                    for(auto& rot: col_rotations[i]){
                        if(rot == 0){
                            zero_indices.push_back(j);
                            break;
                        }
                        j++;
                    }
                }

                std::uint16_t sum = fixed_values_points;
                std::size_t i = 0;
                for(; i < PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns; i++){
                    zero_indices[i] = (sum + zero_indices[i]) * 0x20;
                    sum += col_rotations[i].size();
                    result << std::hex << std::setfill('0') << std::setw(4) << zero_indices[i];
                }

                sum = 0;
                for(; i < PlaceholderParams::total_columns; i++){
                    zero_indices[i] = (sum + zero_indices[i]) * 0x20;
                    sum += col_rotations[i].size() + 1;
                    result << std::hex << std::setfill('0') << std::setw(4) << zero_indices[i];
                }
                return result.str();
            }

            /* Detect whether combination is a polynomial over one variable */
            bool detect_polynomial(crypto3::math::non_linear_combination<variable_type> const& comb) {
                std::unordered_set<variable_type> comb_vars;

                for (auto it = std::begin(comb); it != std::cend(comb); ++it ) {
                    const auto &vars = it->get_vars();
                    for (auto v = std::cbegin(vars); v != std::cend(vars); ++v) {
                        comb_vars.insert(*v);
                    }
                }

                return comb_vars.size() == 1;
            }

            /* Detect whether term is a power of one variable. If such, return this power */
            std::size_t term_is_power(crypto3::math::term<variable_type> const& term) {
                const auto &vars = term.get_vars();
                auto var = std::cbegin(vars);

                if (var == std::cend(vars))
                    return 0;

                variable_type prev_var = *var;
                ++var;

                std::size_t power = 1;

                while (var != std::cend(vars)) {
                    if (*var != prev_var) {
                        return 0;
                    }
                    ++power;
                    prev_var = *var;
                    ++var;
                }

                return power;
            }

            std::string constraint_computation_code_optimized(
                variable_indices_type &_var_indices,
                const constraint_type &constraint
            ){
                std::stringstream result;

                crypto3::math::expression_to_non_linear_combination_visitor<variable_type> visitor;
                auto comb = visitor.convert(constraint);

                if (_deduce_horner && detect_polynomial(comb)) {
                    comb.sort_terms_by_degree();
                    /* First term always exists, as polynomial contains at least one term */
                    std::size_t degree = comb.terms[0].get_vars().size();
                    result << "\t\t/* Constraint is a polynomial over one variable. Using Horner's formula */" << std::endl;
                    auto it = std::cbegin(comb);
                    /* Load temporary variable */
                    result << "\t\tx = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(comb.terms[0].get_vars()[0]) * 0x20 << ");" << std::endl;
                    if (it->get_coeff() == PlaceholderParams::field_type::value_type::one()) {
                        result << "\t\tsum = x;" << std::endl;
                    } else {
                        result << "\t\tsum = " << it->get_coeff() <<";" << std::endl;
                        result << "\t\tsum = mulmod(sum, x, modulus);" << std::endl;
                    }
                    ++it;
                    --degree;
                    while (degree != 0) {
                        if ((degree == it->get_vars().size()) && (it->get_coeff() != 0) ) {
                            result << "\t\tsum = addmod(sum, " << it->get_coeff() << ", modulus);" << std::endl;
                            ++it;
                        } else {
                            result << "\t\t/* term with zero coeficient is skipped */" << std::endl;
                        }
                        result << "\t\tsum = mulmod(sum, x, modulus);" << std::endl;
                        --degree;
                    }
                    if (it != std::cend(comb) && (it->get_coeff() != 0) ) {
                        result << "/* last term */" << std::endl;
                        result << "\t\tsum = addmod(sum, " << it->get_coeff() << ", modulus);" << std::endl;
                    }
                    result << "\t\t/* End using Horner's formula */" << std::endl;
                } else {
                    result << "\t\tsum = 0;" << std::endl;
                    for (auto term = std::cbegin(comb); term != std::cend(comb); ++term) {
                        if ( term->get_coeff() == 0) {
                            continue;
                        }
                        const auto &vars = term->get_vars();
                        std::size_t power;

                        /* Using special powX function is only feasible for powers >= 4 */
                        if ( _optimize_powers && ((power = term_is_power(*term)) >= 4) ) {
                            _term_powers.insert(power);
                            result << "\t\tprod = modular_utils_" << _test_name << ".pow" << power << "(basic_marshalling.get_uint256_be(blob, " << _var_indices.at(vars[0]) * 0x20 << "));" << std::endl;
                        } else {
                            for (auto var = std::cbegin(vars); var != std::cend(vars); ++var) {
                                if (var == std::cbegin(vars)) {
                                    result << "\t\tprod = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(*var) * 0x20 << ");" << std::endl;
                                } else {
                                    result << "\t\tprod = mulmod(prod, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(*var) * 0x20 << "), modulus);" << std::endl;
                                }
                            }
                        }
                        if (vars.size() == 0) {
                            result << "\t\tsum = addmod(sum, " << term->get_coeff() << ", modulus);" << std::endl;
                        } else {
                            if (term->get_coeff() != PlaceholderParams::field_type::value_type::one()) {
                                result << "\t\tprod = mulmod(prod, " << term->get_coeff() << ", modulus);" << std::endl;
                            }
                            result << "\t\tsum = addmod(sum, prod, modulus);" << std::endl;
                        }
                    }
                }
                return result.str();
            }

            std::string constraint_computation_code(
                variable_indices_type &_var_indices,
                const constraint_type &constraint
            ){
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
                std::stringstream result;

                crypto3::math::expression_to_non_linear_combination_visitor<variable_type> visitor;
                auto comb = visitor.convert(constraint);
                result << "\t\tsum = 0;" << std::endl;
                for( auto it = std::cbegin(comb); it != std::cend(comb); ++it ){
                    bool coeff_one = (it->get_coeff() == PlaceholderParams::field_type::value_type::one());
                    if(!coeff_one) result << "\t\tprod = " << it->get_coeff() << ";" << std::endl;
                    const auto &vars = it->get_vars();
                    for( auto it2 = std::cbegin(vars); it2 != std::cend(vars); it2++ ){
                        const variable_type &v = *it2;
                        if(coeff_one){
                            coeff_one = false;
                            result << "\t\tprod = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(v) * 0x20 << ");" << std::endl;
                        } else{
                            result << "\t\tprod = mulmod(prod, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(v) * 0x20 << "), modulus);" << std::endl;
                        }
                    }
                    result << "\t\tsum = addmod(sum, prod, modulus);" << std::endl;
                }
                return result.str();
            }
        public:
            evm_verifier_printer(
                const typename PlaceholderParams::constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const typename PlaceholderParams::commitment_scheme_type &lpc_scheme,
                std::size_t permutation_size,
                std::string folder_name,
                std::size_t gates_contract_size_threshold = 800,
                std::size_t lookups_library_size_threshold = 1000,
                std::size_t lookups_contract_size_threshold = 1000,
                bool deduce_horner = true,
                bool optimize_powers = true
            ) :
            _constraint_system(constraint_system),
            _common_data(common_data),
            _lpc_scheme(lpc_scheme),
            _permutation_size(permutation_size),
            _folder_name(folder_name),
            _lookups_library_size_threshold(lookups_library_size_threshold),
            _gates_contract_size_threshold(gates_contract_size_threshold),
            _lookups_contract_size_threshold(lookups_contract_size_threshold),
            _deduce_horner(deduce_horner),
            _optimize_powers(optimize_powers)
            {
                std::size_t found = folder_name.rfind("/");
                if( found == std::string::npos ){
                    _test_name = folder_name;
                } else{
                    _test_name = folder_name.substr(found + 1);
                }
                _use_lookups = _constraint_system.lookup_gates().size() > 0;

                _z_offset = _use_lookups ? 0xc9 : 0xa1;
                _special_selectors_offset = _z_offset + _permutation_size * 0x80;
                _table_z_offset = _special_selectors_offset + 0xc0;
                _variable_values_offset = 0;

                for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::constant_columns + PlaceholderParams::arithmetization_params::selector_columns; i++){
                    _variable_values_offset += 0x20 * (_common_data.columns_rotations[i + PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns].size()+1);
                }

                _permutation_offset = _variable_values_offset;
                _public_input_offset = _variable_values_offset;
                for( std::size_t i = 0; i < PlaceholderParams::arithmetization_params::witness_columns + PlaceholderParams::arithmetization_params::public_input_columns; i++){
                    if(i == PlaceholderParams::arithmetization_params::witness_columns){
                        _public_input_offset = _permutation_offset;
                    }
                    _permutation_offset += 0x20 * (_common_data.columns_rotations[i].size());
                }

                _quotient_offset = _use_lookups? _permutation_offset + 0x80: _permutation_offset + 0x40;

                _var_indices = get_plonk_variable_indices(_common_data.columns_rotations);
            }

            void print_gates_library_file(std::size_t library_id,
                    std::vector<std::size_t> const& gates_list,
                    std::unordered_map<std::size_t, std::string> const& gate_codes) {

                std::string library_gates;

                for (auto i: gates_list) {
                    std::string gate_evaluation = gate_evaluation_template;
                    boost::replace_all(gate_evaluation, "$GATE_ID$" , to_string(i) );
                    boost::replace_all(gate_evaluation, "$GATE_ASSEMBLY_CODE$", gate_codes.at(i));
                    library_gates += gate_evaluation;
                }

                std::string result = modular_external_gate_library_template;
                boost::replace_all(result, "$TEST_NAME$", _test_name);
                boost::replace_all(result, "$GATE_LIB_ID$", to_string(library_id));
                boost::replace_all(result, "$GATES_COMPUTATION_CODE$", library_gates);
                boost::replace_all(result, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));

                std::ofstream out;
                out.open(_folder_name + "/gate_" + to_string(library_id) + ".sol");
                out << result;
                out.close();
            }

            void print_lookups_library_file(std::size_t library_id,
                    std::vector<std::size_t> const& lookups_list,
                    std::unordered_map<std::size_t, std::string> const& lookup_codes) {

                std::string library_lookups;

                for(auto const& i: lookups_list) {
                    std::string lookup_evaluation = lookup_evaluation_template;
                    boost::replace_all(lookup_evaluation, "$LOOKUP_ID$" , to_string(i) );
                    boost::replace_all(lookup_evaluation, "$LOOKUP_ASSEMBLY_CODE$", lookup_codes.at(i));
                    library_lookups += lookup_evaluation;
                }

                std::string result = modular_external_lookup_library_template;
                boost::replace_all(result, "$TEST_NAME$", _test_name);
                boost::replace_all(result, "$LOOKUP_LIB_ID$", to_string(library_id));
                boost::replace_all(result, "$LOOKUP_COMPUTATION_CODE$", library_lookups);
                boost::replace_all(result, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                boost::replace_all(result, "$STATE$", "");

                std::ofstream out;
                out.open(_folder_name + "/lookup_" + to_string(library_id) + ".sol");
                out << result;
                out.close();
            }

            std::string gate_computation_code(const gate_type& gate) {
                std::stringstream out;

                out << "\t\tgate = 0;" << std::endl;
                int c = 0;
                for(const auto &constraint: gate.constraints){
                    out << constraint_computation_code_optimized(_var_indices, constraint);
                    out << "\t\tgate = addmod(gate, mulmod(theta_acc, sum, modulus), modulus);" << std::endl;
                    out << "\t\ttheta_acc = mulmod(theta_acc, theta, modulus);" << std::endl;
                    c++;
                }
                variable_type sel_var(gate.selector_index, 0, true, variable_type::column_type::selector);
                out << "\t\tgate = mulmod(gate, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << "), modulus);" << std::endl;
                out << "\t\tF = addmod(F, gate, modulus);" <<std::endl;
                return out.str();
            }

            std::string lookup_computation_code(const lookup_gate_type& gate){
                std::stringstream out;

                variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                out << "\t\t$STATE$selector_value=basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << ");" << std::endl;
                for( const auto &constraint: gate.constraints ){
                    variable_type sel_var(gate.tag_index, 0, true, variable_type::column_type::selector);
                    out << "\t\tl = mulmod( " << constraint.table_id << ",$STATE$selector_value, modulus);" << std::endl;
                    out << "\t\t$STATE$theta_acc=$STATE$theta;" << std::endl;
                    for( const auto &expression:constraint.lookup_input ){
                        out << constraint_computation_code(_var_indices, expression) << std::endl  << std::endl;
                        out << "\t\tl = addmod( l, mulmod( mulmod($STATE$theta_acc, $STATE$selector_value, modulus), sum, modulus), modulus);" << std::endl;
                        out << "\t\t$STATE$theta_acc = mulmod($STATE$theta_acc, $STATE$theta, modulus);" << std::endl;
                    }
                    out << "\t\t$STATE$g = mulmod($STATE$g, mulmod(addmod(1, $STATE$beta, modulus), addmod(l, $STATE$gamma, modulus), modulus), modulus);" << std::endl;
                }

                return out.str();
            }

            std::size_t estimate_constraint_cost(std::string const& code) {
                /* proof-of-concept: cost = number of lines */
                std::size_t lines = 0;
                for(auto &ch: code) {
                    lines += ch == '\n';
                }
                return lines;
            }

            std::size_t estimate_gate_cost(std::string const& code) {
                /* proof-of-concept: cost = number of lines */
                std::size_t lines = 0;
                for(auto &ch: code) {
                    lines += ch == '\n';
                }
                return lines;
            }

            std::size_t estimate_lookup_cost(std::string const& code) {
                /* proof-of-concept: cost = number of lines */
                std::size_t lines = 0;
                for(auto &ch: code) {
                    lines += ch == '\n';
                }
                return lines;
            }

            /** @brief Split items into buckets, each bucket is limited
             * to max_bucket_size, minimizes number of buckets.
             * items must be sorted
             * @param[in] items (item_id, item_size)
             * @param[in] max_bucket_size
             * @returns buckets (bucket_id -> [item_id])
             * */
            std::unordered_map<std::size_t, std::vector<std::size_t>> split_items_into_buckets(
                    std::vector<std::pair<std::size_t, std::size_t>> &items,
                    std::size_t max_bucket_size) {

                std::unordered_map<std::size_t, std::vector<std::size_t>> buckets;
                std::vector<std::size_t> bucket_sizes;

                for (auto const& item : items) {
                    bool bucket_found = false;
                    for (std::size_t i = 0; i < bucket_sizes.size(); ++i) {
                        if (bucket_sizes[i]+item.second <= max_bucket_size) {
                            buckets[i].push_back(item.first);
                            bucket_sizes[i] += item.second;
                            bucket_found = true;
                            break;
                        }
                    }

                    if (!bucket_found) {
                        bucket_sizes.push_back(item.second);
                        buckets[bucket_sizes.size()-1].push_back(item.first);
                    }
                }
                return buckets;
            }

            std::string generate_power_function(std::size_t power) {
                std::stringstream result;
                std::vector<std::string> ops;

                result << "\tfunction pow" << power << "(uint256 base) internal pure returns (uint256 result) {" << std::endl;
                result << "\t\tresult = base;" << std::endl;

                while (power > 1) {
                    if (power & 1) {
                        ops.push_back("\t\tresult = mulmod(result, base, modulus);");
                    }
                    ops.push_back("\t\tresult = mulmod(result, result, modulus);");
                    power >>= 1;
                }

                for(auto op = ops.rbegin(); op != ops.rend(); ++op) {
                    result << *op << std::endl;
                }

                result << "\t}" << std::endl;
                return result.str();
            }

            struct constraint_info {
                std::string code;
                std::size_t cost;
                std::size_t gate_index;
                std::size_t constraint_index;
                std::size_t selector_index;
            };

            std::string print_constraint_series(typename std::vector<constraint_info>::iterator &it,
                    typename std::vector<constraint_info>::iterator const& last) {
                std::stringstream result;
                std::size_t printed_cost = 0;
                std::size_t prev_sel = 0;

                bool first_constraint = true;

                while ((printed_cost <= _gates_contract_size_threshold) && (it != last) ) {

                    if (first_constraint) {
                        result << "// gate === " << it->gate_index << " ===" << std::endl;
                        result << "\t\tgate = 0;" << std::endl;
                        first_constraint = false;
                        prev_sel = it->selector_index;
                    } else if (prev_sel != it->selector_index) {
                        result << "\t\tgate = mulmod(gate, basic_marshalling.get_uint256_be(blob, "<<prev_sel<<"), modulus);" << std::endl;
                        result << "\t\tF = addmod(F, gate, modulus);" << std::endl;
                        result << "// gate === " << it->gate_index << " ===" << std::endl;
                        result << "\t\tgate = 0;" << std::endl;
                        prev_sel = it->selector_index;
                    }
                    result << "// constraint " << it->constraint_index << std::endl;
                    result << it->code;
                    result << "\t\tsum = mulmod(sum, theta_acc, modulus);" << std::endl;
                    result << "\t\ttheta_acc = mulmod(theta, theta_acc, modulus);" << std::endl;
                    result << "\t\tgate = addmod(gate, sum, modulus);" << std::endl;

                    printed_cost += it->cost;
                    ++it;
                }

                if (it != last) {
                    result << "// gate computation code ended prematurely. continue in next library" << std::endl;
                }
                result << "\t\tgate = mulmod(gate, basic_marshalling.get_uint256_be(blob, "<<prev_sel<<"), modulus);" << std::endl;
                result << "\t\tF = addmod(F, gate, modulus);" << std::endl;

                return result.str();
            }

            std::string print_gate_argument(){
                std::size_t gates_count = _constraint_system.gates().size();
                if (gates_count == 0)
                    return "";

                std::stringstream gate_argument_str;
                std::size_t i = 0;
                std::unordered_map<std::size_t, std::string> gate_codes;
                std::vector<std::pair<std::size_t, std::size_t>> gate_costs(gates_count);
                std::vector<std::size_t> gate_ids(gates_count);

                std::vector<constraint_info> constraints;
                std::size_t total_cost = 0;

                i = 0;
                for (const auto& gate: _constraint_system.gates()) {
                    variable_type sel_var(gate.selector_index, 0, true, variable_type::column_type::selector);
                    std::size_t j = 0;
                    for (const auto& constraint: gate.constraints) {
                        std::string code = constraint_computation_code_optimized(_var_indices, constraint);
                        std::size_t cost = estimate_constraint_cost(code);
                        std::size_t selector_index = _var_indices.at(sel_var)*0x20;

                        constraints.push_back( {code, cost, i, j, selector_index} );

                        total_cost += cost;
                        ++j;
                    }
                    ++i;
                }


                std::size_t gate_modules_count = 0;
                std::size_t current_selector = 0;
                if (total_cost <= _gates_contract_size_threshold) {
                    auto it = constraints.begin();
                    gate_argument_str << "\t\tuint256 prod;" << std::endl;
                    gate_argument_str << "\t\tuint256 sum;" << std::endl;
                    gate_argument_str << "\t\tuint256 gate;" << std::endl;
                    gate_argument_str << print_constraint_series(it, constraints.end());
                } else {
                    auto it = constraints.begin();
                    while (it != constraints.end()) {
                        std::string code = print_constraint_series(it, constraints.end());

                        std::string result = modular_external_gate_library_template;
                        boost::replace_all(result, "$TEST_NAME$", _test_name);
                        boost::replace_all(result, "$GATE_LIB_ID$", to_string(gate_modules_count));
                        boost::replace_all(result, "$CONSTRAINT_SERIES_CODE$", code);
                        boost::replace_all(result, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                        boost::replace_all(result, "$UTILS_LIBRARY_IMPORT$", _term_powers.size() >0? "import \"./utils.sol\";" : "");


                        std::ofstream out;
                        out.open(_folder_name + "/gate_" + to_string(gate_modules_count) + ".sol");
                        out << result;
                        out.close();
                        _gate_includes += "import \"./gate_" + to_string(gate_modules_count) + ".sol\";\n";

                        ++gate_modules_count;
                    }
                }
                std::cout << "Finished" << std::endl;

                if (_term_powers.size() > 0) {
                    std::stringstream power_functions;
                    for(std::size_t power: _term_powers) {
                        power_functions << generate_power_function(power);
                    }

                    std::string utils_library(utils_library_template);
                    boost::replace_all(utils_library, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                    boost::replace_all(utils_library, "$POWER_FUNCTIONS$", power_functions.str());
                    boost::replace_all(utils_library, "$TEST_NAME$", _test_name);
                    std::ofstream utils;
                    utils.open(_folder_name + "/utils.sol");
                    utils << utils_library;
                    utils.close();
                }

                for ( i = 0; i < gate_modules_count; ++i ) {
                    std::string gate_eval_string = gate_call_template;
                    boost::replace_all(gate_eval_string, "$TEST_NAME$", _test_name);
                    boost::replace_all(gate_eval_string, "$GATE_LIB_ID$", to_string(i));
                    gate_argument_str << gate_eval_string << std::endl;
                }
                i = 0;

                if ( gate_modules_count > 0) {
                    std::ofstream out;
                    out.open(_folder_name + "/gate_libs_list.json");
                    out << "[" << std::endl;
                    for(i = 0; i < gate_modules_count-1; ++i ) {
                        out << "\"" << "gate_" << _test_name << "_" << i << "\"," << std::endl;
                    }
                    out << "\"" << "gate_" << _test_name << "_" << gate_modules_count-1 << "\"" << std::endl;
                    out << "]" << std::endl;
                    out.close();
                }

                return gate_argument_str.str();
            }

            std::string print_lookup_argument(){
                std::size_t lookup_count = _constraint_system.lookup_gates().size();
                if (lookup_count == 0)
                    return "";

                std::stringstream lookup_str;
                std::size_t j = 0;
                std::size_t i = 0;
                std::size_t cur = 0;
                std::unordered_map<std::size_t, std::string> lookup_codes;
                std::vector<std::size_t> lookup_ids(lookup_count);
                std::vector<std::pair<std::size_t, std::size_t>> lookup_costs(lookup_count);
                std::vector<std::size_t> lookup_lib(lookup_count);

                i = 0;
                for(const auto &lookup: _constraint_system.lookup_gates()) {
                    std::string code = lookup_computation_code(lookup);
                    lookup_costs[i] = std::make_pair(i, estimate_lookup_cost(code));
                    lookup_codes[i] = code;
                    ++i;
                }

                std::sort(lookup_costs.begin(), lookup_costs.end(),
                        [](const std::pair<std::size_t, std::size_t> &a,
                            const std::pair<std::size_t, std::size_t> &b) {
                        return a.second > b.second;
                        });

                /* Fill contract inline lookup computation, inline small first */
                std::unordered_set<std::size_t> inlined_lookup_codes;
                std::size_t inlined_lookup_codes_size = 0;
                for (auto lookup = lookup_costs.rbegin(); lookup != lookup_costs.rend(); ++lookup) {
                    if (lookup->second + inlined_lookup_codes_size < _lookups_contract_size_threshold) {
                        inlined_lookup_codes.insert(lookup->first);
                        inlined_lookup_codes_size += lookup->second;
                    }
                }

                auto inlined_lookups_end = std::remove_if(lookup_costs.begin(), lookup_costs.end(),
                    [&inlined_lookup_codes](const std::pair<std::size_t, std::size_t>& cost) {
                        return inlined_lookup_codes.count(cost.first) == 1 ;
                    });
                lookup_costs.erase(inlined_lookups_end, lookup_costs.end());

                auto library_lookup_buckets = split_items_into_buckets(lookup_costs, _lookups_library_size_threshold);

                _lookup_includes = "";
                for(auto const& lib: library_lookup_buckets) {
                    _lookup_includes += "import \"./lookup_"  + to_string(lib.first) + ".sol\";\n";
                    for(auto l: lib.second) {
                        lookup_lib[l] = lib.first;
                    }
                    print_lookups_library_file(lib.first, lib.second, lookup_codes);
                }

                if (inlined_lookup_codes.size() > 0) {
                    lookup_str << "\t\t\tuint256 sum;" << std::endl;
                    lookup_str << "\t\t\tuint256 prod;" << std::endl;
                }

                for (i = 0; i < _constraint_system.lookup_gates().size(); ++i) {
                    if (inlined_lookup_codes.count(i) == 1) {
                        boost::replace_all(lookup_codes[i], "$STATE$", "state.");
                        lookup_str << "/* -- lookup " << i << " is inlined -- */" << std::endl;
                        lookup_str << lookup_codes[i] << std::endl;
                        lookup_str << "/* -- /lookup " << i << " is inlined -- */" << std::endl;
                    } else {
                        std::string lookup_eval_string = lookup_call_template;
                        boost::replace_all(lookup_eval_string, "$TEST_NAME$", _test_name);
                        boost::replace_all(lookup_eval_string, "$LOOKUP_LIB_ID$", to_string(lookup_lib[i]));
                        boost::replace_all(lookup_eval_string, "$LOOKUP_ID$", to_string(i));
                        boost::replace_all(lookup_eval_string, "$MODULUS$", to_string(PlaceholderParams::field_type::modulus));
                        lookup_str << lookup_eval_string;
                    }
                }

                if (library_lookup_buckets.size() > 0) {
                    std::ofstream out;
                    out.open(_folder_name + "/lookup_libs_list.json");
                    out << "[" << std::endl;
                    for(i = 0; i < library_lookup_buckets.size()-1; ++i ) {
                        out << "\"" << "lookup_" << _test_name << "_" << i << "\"," << std::endl;
                    }
                    out << "\"" << "lookup_" << _test_name << "_" << library_lookup_buckets.size()-1 << "\"" << std::endl;
                    out << "]" << std::endl;
                    out.close();
                }

                j = 0;
                std::size_t table_index = 1;
                for(const auto &table: _constraint_system.lookup_tables()){
                    variable_type sel_var(table.tag_index, 0, true, variable_type::column_type::selector);
                    variable_type shifted_sel_var(table.tag_index, 1, true, variable_type::column_type::selector);
                    lookup_str << "\t\t\tstate.selector_value = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(sel_var) * 0x20 << ");" << std::endl;
                    lookup_str << "\t\t\tstate.shifted_selector_value = basic_marshalling.get_uint256_be(blob, " << _var_indices.at(shifted_sel_var) * 0x20 << ");" << std::endl;

                    for( const auto &option: table.lookup_options ){
                        lookup_str <<
                            "\t\t\tl = mulmod( " << table_index << ", state.selector_value, modulus);" << std::endl;
                        lookup_str <<
                            "\t\t\tstate.l_shifted = mulmod( " << table_index << ", state.shifted_selector_value, modulus);" << std::endl;
                        lookup_str << "\t\t\tstate.theta_acc=state.theta;" << std::endl;
                        for( const auto &var: option ){
                            lookup_str <<
                                "\t\t\tl = addmod( l, mulmod(state.selector_value,  mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                            variable_type shifted_var = var;
                            shifted_var.rotation = 1;
                            lookup_str <<
                                "\t\t\tstate.l_shifted = addmod( state.l_shifted, mulmod(state.shifted_selector_value, mulmod( state.theta_acc, basic_marshalling.get_uint256_be(blob, " << _var_indices.at(shifted_var) * 0x20 << "), modulus), modulus), modulus);" << std::endl;
                            lookup_str << "\t\t\tstate.theta_acc = mulmod(state.theta_acc, state.theta, modulus);" << std::endl;
                        }
                        lookup_str <<
                            "\t\t\tl = mulmod( l, state.mask, modulus);" << std::endl;
                        lookup_str <<
                            "\t\t\tstate.l_shifted = mulmod( state.l_shifted, state.shifted_mask, modulus);" << std::endl;
                        lookup_str << "\t\t\tstate.g = mulmod(state.g, addmod( state.factor, addmod(l, mulmod(state.beta, state.l_shifted, modulus), modulus), modulus), modulus);" << std::endl;
                        j++;
                    }
                    table_index++;
                }
                lookup_str << std::endl;

                return lookup_str.str();
            }

            std::string eta_point_verification_code() {
                std::stringstream result;
                auto fixed_poly_values = _common_data.commitment_scheme_data;
                using eta_hash = crypto3::hashes::keccak_1600<256>;
                using field_element_type = nil::crypto3::marshalling::types::field_element<
                                nil::marshalling::field_type<nil::marshalling::option::big_endian>,
                                typename PlaceholderParams::field_type::value_type>;

                if (fixed_poly_values.size() == 0)
                    return "";

                std::vector<std::uint8_t> eta_buf;

                std::size_t poly_points = 2*_permutation_size;
                /* special_selectors */
                poly_points += 2;
                poly_points += PlaceholderParams::arithmetization_params::constant_columns;
                poly_points += PlaceholderParams::arithmetization_params::selector_columns;
                eta_buf.resize( 32*poly_points );

                std::array<std::uint8_t, 0> empty;
                auto writer = eta_buf.begin();

                result << "\t\t/* eta points check */" << std::endl;
                result << "\t\t{" << std::endl;
                result << "\t\t\tuint256[" << poly_points << "] memory points;" << std::endl;

                std::size_t i = 0, j = 0;
                std::size_t point_offset = 8;


                result << std::showbase << std::hex;

                result << "\t\t\t// 1. 2*permutation_size" << std::endl;
                poly_points = 2;

                while (j < 2*_permutation_size) {
                    result << "\t\t\tpoints[" << i << "] = basic_marshalling.get_uint256_be(blob,";
                    result << point_offset + (poly_points-1)*32 << ");" << std::endl;
                    field_element_type value(fixed_poly_values[0][i]);
                    value.write(writer, 32);
                    point_offset += 32*poly_points;
                    ++i;
                    ++j;
                }

                result << "\t\t\t// 2. special selectors " << std::endl;
                poly_points = 3;

                j = 0;
                while (j < 2) {
                    result << "\t\t\tpoints[" << i << "] = basic_marshalling.get_uint256_be(blob,";
                    result << point_offset + (poly_points-1)*32 << ");" << std::endl;
                    field_element_type value(fixed_poly_values[0][i]);
                    value.write(writer, 32);
                    point_offset += 32*poly_points;
                    ++i;
                    ++j;
                }

                result << "\t\t\t// 3. constant columns " << std::endl;
                std::size_t column_rotation_offset = PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns;
                j = 0;
                while (j < PlaceholderParams::arithmetization_params::constant_columns) {
                    poly_points = _common_data.columns_rotations[column_rotation_offset + j].size()+1;
                    result << "\t\t\tpoints[" << i << "] = basic_marshalling.get_uint256_be(blob,";
                    result << point_offset + (poly_points-1)*32 << ");" << std::endl;
                    field_element_type value(fixed_poly_values[0][i]);
                    value.write(writer, 32);
                    point_offset += 32*poly_points;
                    ++i;
                    ++j;
                }

                result << "\t\t\t// 4. selector columns " << std::endl;
                column_rotation_offset += PlaceholderParams::constant_columns;
                j = 0;
                while (j < PlaceholderParams::arithmetization_params::selector_columns) {
                    poly_points = _common_data.columns_rotations[column_rotation_offset + j].size()+1;
                    result << "\t\t\tpoints[" << i << "] = basic_marshalling.get_uint256_be(blob,";
                    result << point_offset + (poly_points-1)*32 << ");" << std::endl;
                    field_element_type value(fixed_poly_values[0][i]);
                    value.write(writer, 32);
                    point_offset += 32*(poly_points);
                    ++i;
                    ++j;
                }

                eta_hash::digest_type hash_result = crypto3::hash<eta_hash>(eta_buf);
                result << "\t\t\t// Check keccak(points) " << std::endl;
                result << "\t\t\tif ( bytes32(0x" << std::to_string(hash_result).data() << ") != keccak256(abi.encode(points))) {" << std::endl;
                result << "\t\t\t\treturn false;" << std::endl;
                result << "\t\t\t}" << std::endl;
                result << "\t\t}" << std::endl;

                return result.str();
            }

            void print(){
                std::filesystem::create_directory(_folder_name);
                std::cout << "Generating verifier " << _test_name << std::endl;

                std::string gate_argument = print_gate_argument();
                std::string lookup_argument = print_lookup_argument();

                std::string commitment_code = generate_commitment_scheme_code<PlaceholderParams>(_common_data, _lpc_scheme);

                // Prepare all necessary replacements
                transpiler_replacements reps;
                reps["$LOOKUP_LIBRARY_CALL$"] = _use_lookups ? lookup_library_call :"        //No lookups";
                reps["$TEST_NAME$"] = _test_name;
                reps["$MODULUS$"] = to_string(PlaceholderParams::field_type::modulus);
                reps["$VERIFICATION_KEY1$"] = "0x" + to_string(_common_data.vk.constraint_system_hash);
                reps["$VERIFICATION_KEY2$"] = "0x" + to_string(_common_data.vk.fixed_values_commitment);
                reps["$BATCHES_NUM$"] = _use_lookups ? "5" :"4";
                reps["$EVAL_PROOF_OFFSET$"] = _use_lookups ? "0xa1" :"0x79";
                reps["$SORTED_COLUMNS_NUMBER$"] = to_string(_constraint_system.sorted_lookup_columns_number());
                reps["$LOOKUP_OPTIONS_NUMBER$"] = to_string(_constraint_system.lookup_options_num());
                reps["$LOOKUP_CONSTRAINTS_NUMBER$"] = to_string(_constraint_system.lookup_constraints_num());
                reps["$Z_OFFSET$"] = _use_lookups ? "0xc9" :"0xa1";
                reps["$PERMUTATION_SIZE$"] = to_string(_permutation_size);
                reps["$SPECIAL_SELECTORS_OFFSET$"] = to_string(_special_selectors_offset);
                reps["$TABLE_Z_OFFSET$"] = to_string(_table_z_offset);
                reps["$PUBLIC_INPUT_OFFSET$"] = to_string(_public_input_offset);
                reps["$PERMUTATION_TABLE_OFFSET$"] = to_string(_permutation_offset);
                reps["$QUOTIENT_OFFSET$"] = to_string(_quotient_offset);
                reps["$ROWS_AMOUNT$"] = to_string(_common_data.rows_amount);
                reps["$OMEGA$"] = to_string(_common_data.basic_domain->get_domain_element(1));
                reps["$ZERO_INDICES$"] = zero_indices(_common_data.columns_rotations);
                reps["$GATE_ARGUMENT_COMPUTATION$"] = gate_argument;
                reps["$GATE_INCLUDES$"] = _gate_includes;
                reps["$LOOKUP_INCLUDES$"] = _lookup_includes;
                reps["$LOOKUP_ARGUMENT_COMPUTATION$"] = lookup_argument;
                reps["$COMMITMENT_CODE$"] = commitment_code;
                reps["$ETA_VALUES_VERIFICATION$"] = eta_point_verification_code();

                commitment_scheme_replaces<PlaceholderParams>(reps, _common_data, _lpc_scheme, _permutation_size, _use_lookups);

                replace_and_print(modular_verifier_template, reps, _folder_name + "/modular_verifier.sol");
                replace_and_print(modular_permutation_argument_library_template, reps, _folder_name + "/permutation_argument.sol");
                replace_and_print(modular_gate_argument_library_template, reps, _folder_name + "/gate_argument.sol");
                replace_and_print(modular_commitment_library_template, reps, _folder_name + "/commitment.sol");
                if(_use_lookups)
                    replace_and_print(modular_lookup_argument_library_template, reps, _folder_name + "/lookup_argument.sol");
                else
                    replace_and_print(modular_dummy_lookup_argument_library_template, reps, _folder_name + "/lookup_argument.sol");
            }

        private:
            const typename PlaceholderParams::constraint_system_type &_constraint_system;
            const common_data_type &_common_data;
            const typename PlaceholderParams::commitment_scheme_type &_lpc_scheme;
            std::size_t _permutation_size;
            std::string _folder_name;
            std::string _test_name;
            bool        _use_lookups;
            std::size_t _z_offset;
            std::size_t _special_selectors_offset;
            std::size_t _table_z_offset;
            std::size_t _variable_values_offset;
            std::size_t _permutation_offset;
            std::size_t _quotient_offset;
            std::size_t _public_input_offset;
            variable_indices_type _var_indices;

            bool _deduce_horner;

            bool _optimize_powers;
            std::unordered_set<std::size_t> _term_powers;

            std::string _gate_includes;
            std::string _lookup_includes;
            std::size_t _gates_contract_size_threshold;
            std::size_t _lookups_contract_size_threshold;
            std::size_t _lookups_library_size_threshold;
        };
    }
}

#endif //__MODULAR_CONTRACTS_TEMPLATES_HPP__
