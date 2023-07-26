//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/copy_constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/lookup_constraint.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                /*********************** Plonk constraint ****************************/
                template<typename TTypeBase, typename PlonkConstraint>
                using plonk_constraint =
                    typename expression<TTypeBase, typename PlonkConstraint::base_type>::type;

                template<typename PlonkConstraint, typename Endianness,  typename = typename std::enable_if<
                             std::is_same<PlonkConstraint, nil::crypto3::zk::snark::plonk_constraint<
                                                               typename PlonkConstraint::field_type,
                                                               typename PlonkConstraint::variable_type>>::value>::type>
                plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint>
                fill_plonk_constraint(const PlonkConstraint &constr) {
                    return fill_expression<typename PlonkConstraint::base_type, Endianness>(constr);
                }

                template<typename PlonkConstraint, typename Endianness,  typename = typename std::enable_if<
                             std::is_same<PlonkConstraint, nil::crypto3::zk::snark::plonk_constraint<
                                                               typename PlonkConstraint::field_type,
                                                               typename PlonkConstraint::variable_type>>::value>::type>
                PlonkConstraint make_plonk_constraint(
                    const plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint> &filled_constr
                ) {
                    return make_expression<typename PlonkConstraint::base_type, Endianness>(filled_constr);
                }

                /*********************** Plonk lookup constraint ****************************/
                template<typename TTypeBase, typename PlonkLookupConstraint>
                using plonk_lookup_constraint = nil::marshalling::types::bundle<
                    TTypeBase, std::tuple<                  
                        // std::vector<math::term<VariableType>> lookup_input;          
                        nil::marshalling::types::array_list<
                            TTypeBase, typename term<TTypeBase, typename PlonkLookupConstraint::term>::type,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                        >,
                        //  std::vector<VariableType> lookup_value;
                        nil::crypto3::marshalling::types::variables<TTypeBase, typename PlonkLookupConstraint::field_type::value_type>
                    >
                >;

                // Plonk_constraint and plonk_lookup_constraint are template inputs for plonk_gate types.
                // That's why we use the same marshalling function names for them.
                template<typename PlonkLookupConstraint, typename Endianness,  typename = typename std::enable_if<
                             std::is_same<PlonkLookupConstraint, nil::crypto3::zk::snark::plonk_lookup_constraint<
                                                               typename PlonkLookupConstraint::field_type,
                                                               typename PlonkLookupConstraint::variable_type>>::value>::type>
                plonk_lookup_constraint<nil::marshalling::field_type<Endianness>, PlonkLookupConstraint>
                fill_plonk_constraint(const PlonkLookupConstraint &constr) {

                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    using result_type = plonk_lookup_constraint<TTypeBase, PlonkLookupConstraint>;

                    nil::marshalling::types::array_list<
                            TTypeBase, typename term<TTypeBase, typename PlonkLookupConstraint::term>::type,
                            nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                    > filled_lookup_input;
                    for(std::size_t i = 0; i < constr.lookup_input.size(); i++){
                        filled_lookup_input.value().push_back(
                            fill_term<typename PlonkLookupConstraint::term, Endianness>(constr.lookup_input[i])
                        );
                    }

                    auto filled_variables = fill_variables<typename PlonkLookupConstraint::variable_type, Endianness>(constr.lookup_value);

                    return result_type(std::make_tuple(
                        filled_lookup_input,
                        filled_variables
                    ));
                }

                template<typename PlonkLookupConstraint, typename Endianness,  typename = typename std::enable_if<
                             std::is_same<PlonkLookupConstraint, nil::crypto3::zk::snark::plonk_lookup_constraint<
                                                               typename PlonkLookupConstraint::field_type,
                                                               typename PlonkLookupConstraint::variable_type>>::value>::type>
                PlonkLookupConstraint make_plonk_constraint(
                    const plonk_lookup_constraint<nil::marshalling::field_type<Endianness>, PlonkLookupConstraint> &filled_constr
                ) {
                    PlonkLookupConstraint lookup_constraint;
                    auto filled_lookup_input = std::get<0>(filled_constr.value());
                    for(size_t i = 0; i < filled_lookup_input.value().size(); i++){
                        lookup_constraint.lookup_input.emplace_back(
                            make_term<typename PlonkLookupConstraint::term, Endianness>(
                                filled_lookup_input.value().at(i)
                            )
                        );
                    }
                    lookup_constraint.lookup_value = make_variables<typename PlonkLookupConstraint::variable_type, Endianness>(
                        std::get<1>(filled_constr.value())
                    );

                    return lookup_constraint;
                }

                /*********************** Plonk gates constraints  ****************************/
                /*                 Universal interface for gates marshalling                 */
                /*****************************************************************************/
                
                //TODO maybe it can be implemented in a better way

                template <typename TTypeBase, typename Constraint, typename T=void > 
                struct plonk_gate_constraint_base_type;

                template <typename TTypeBase, typename Constraint> 
                struct plonk_gate_constraint_base_type< TTypeBase, Constraint, nil::crypto3::zk::snark::plonk_constraint<
                    typename Constraint::field_type,
                    typename Constraint::variable_type
                >>
                {
                    using type = plonk_constraint<TTypeBase, Constraint>;
                };

                template <typename TTypeBase, typename Constraint> 
                struct plonk_gate_constraint_base_type< TTypeBase, Constraint, nil::crypto3::zk::snark::plonk_lookup_constraint<
                    typename Constraint::field_type,
                    typename Constraint::variable_type
                >>
                {
                    using type = plonk_lookup_constraint<TTypeBase, Constraint>;
                };

                template <typename TTypeBase, typename Constraint> 
                using plonk_gate_constraint = plonk_gate_constraint_base_type<TTypeBase, Constraint, Constraint>;

                /*********************** Universal vector of plonk constraints as input to gate ****************************/
                template<typename TTypeBase, typename Constraint>
                using plonk_constraints = nil::marshalling::types::array_list<
                    TTypeBase, 
                    typename plonk_gate_constraint<TTypeBase, Constraint>::type,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Constraint, typename Endianness>
                plonk_constraints<nil::marshalling::field_type<Endianness>, Constraint>
                fill_plonk_constraints(const std::vector<Constraint> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_constraints<TTypeBase, Constraint> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(fill_plonk_constraint<Constraint, Endianness>(constraint));
                    }

                    return filled_constraints;
                }

                template<typename Constraint, typename Endianness>
                std::vector<Constraint>
                make_plonk_constraints(const plonk_constraints<nil::marshalling::field_type<Endianness>, Constraint> &filled_constraints){
                    std::vector<Constraint> constraints;
                    for (auto i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_constraint<Constraint, Endianness>(filled_constraints.value().at(i)));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
