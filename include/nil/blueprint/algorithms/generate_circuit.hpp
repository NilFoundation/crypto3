//---------------------------------------------------------------------------//
// Copyright (c) 2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2022 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_ZK_COMPONENTS_ALGORITHMS_GENERATE_CIRCUIT_HPP
#define CRYPTO3_ZK_COMPONENTS_ALGORITHMS_GENERATE_CIRCUIT_HPP

#include <boost/type_traits.hpp>
#include <boost/tti/tti.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace crypto3 {
        namespace blueprint {
            namespace components {

                BOOST_TTI_HAS_STATIC_MEMBER_FUNCTION(generate_circuit)

                template<typename ComponentType, typename ArithmetizationType>
                typename std::enable_if<
                    (!(has_static_member_function_generate_circuit<ComponentType,
                            typename ComponentType::result_type,
                        boost::mpl::vector<blueprint<ArithmetizationType> &,
                            blueprint_public_assignment_table<ArithmetizationType> &,
                            const typename ComponentType::params_type &,
                            const std::size_t>>::value)),
                        typename ComponentType::result_type>::type
                    generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const typename ComponentType::params_type & params,
                        const std::size_t start_row_index){

                    auto selector_iterator = assignment.find_selector(ComponentType::selector_seed);
                    std::size_t first_selector_index;

                    if (selector_iterator == assignment.selectors_end()){
                        first_selector_index = assignment.allocate_selector(ComponentType::selector_seed,
                            ComponentType::gates_amount);
                        ComponentType::generate_gates(bp, assignment, params, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }

                    assignment.enable_selector(first_selector_index, start_row_index);

                    ComponentType::generate_copy_constraints(bp, assignment, params, start_row_index);

                    return typename ComponentType::result_type(params, start_row_index);
                }

                template<typename ComponentType, typename ArithmetizationType>
                typename std::enable_if<
                    (has_static_member_function_generate_circuit<ComponentType,
                            typename ComponentType::result_type,
                        boost::mpl::vector<blueprint<ArithmetizationType> &,
                            blueprint_public_assignment_table<ArithmetizationType> &,
                            const typename ComponentType::params_type &,
                            const std::size_t>>::value),
                        typename ComponentType::result_type>::type
                    generate_circuit(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const typename ComponentType::params_type & params,
                        const std::size_t start_row_index){

                    return ComponentType::generate_circuit(bp, assignment, params, start_row_index);
                }

            }    // namespace components
        }    // namespace blueprint
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_COMPONENTS_ALGORITHMS_GENERATE_CIRCUIT_HPP
