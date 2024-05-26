//---------------------------------------------------------------------------//
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>
#include <nil/crypto3/marshalling/zk/types/plonk/constraint.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                // Type is completely different from plonk_lookup_constraint.
                // Because this types of constraints may be processed in different ways.
                // For example selector algorithms may be completely different.
                // *********************** Lookup constraint **************************** //
                template<typename TTypeBase, typename Constraint>
                using plonk_lookup_constraint = nil::marshalling::types::bundle<TTypeBase, std::tuple<
                    nil::marshalling::types::integral<TTypeBase, std::size_t>, // table_id
                    plonk_constraints<TTypeBase, typename Constraint::constraint_type>                   // constraint
                >>;

                template<typename Endianness, typename Constraint>
                plonk_lookup_constraint<nil::marshalling::field_type<Endianness>, Constraint>
                fill_plonk_lookup_constraint(const Constraint &constraint){
                    using TTypeBase = nil::marshalling::field_type<Endianness>;
                    return plonk_lookup_constraint<TTypeBase, Constraint>(
                        std::tuple(
                            nil::marshalling::types::integral<TTypeBase, std::size_t>(constraint.table_id),
                            fill_plonk_constraints<Endianness, typename Constraint::constraint_type>(constraint.lookup_input)
                        )
                    );
                }

                template<typename Endianness, typename Constraint>
                Constraint make_plonk_lookup_constraint(const plonk_lookup_constraint<nil::marshalling::field_type<Endianness>, Constraint> &filled_constraint){
                    return Constraint({
                        std::get<0>(filled_constraint.value()).value(),
                        make_plonk_constraints<Endianness, typename Constraint::constraint_type>(std::get<1>(filled_constraint.value()))
                    });
                }

                // *********************** Vector of lookup constraints for a lookup gate **************************** //
                template<typename TTypeBase, typename Constraint>
                using plonk_lookup_constraints = nil::marshalling::types::array_list<
                    TTypeBase,
                    plonk_lookup_constraint<TTypeBase, Constraint>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename Constraint>
                plonk_lookup_constraints<nil::marshalling::field_type<Endianness>, Constraint>
                fill_plonk_lookup_constraints(const std::vector<Constraint> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_lookup_constraints<TTypeBase, Constraint> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(fill_plonk_lookup_constraint<Endianness, Constraint>(constraint));
                    }

                    return filled_constraints;
                }

                template<typename Endianness, typename Constraint>
                std::vector<Constraint>
                make_plonk_lookup_constraints(const plonk_lookup_constraints<nil::marshalling::field_type<Endianness>, Constraint> &filled_constraints){
                    std::vector<Constraint> constraints;
                    for (std::size_t i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_lookup_constraint<Endianness, Constraint>(filled_constraints.value().at(i)));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_LOOKUP_CONSTRAINT_HPP
