//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
#define CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP

#include <type_traits>

#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/status_type.hpp>
#include <nil/marshalling/options.hpp>

#include <nil/crypto3/marshalling/math/types/term.hpp>
#include <nil/crypto3/marshalling/math/types/expression.hpp>

namespace nil {
    namespace crypto3 {
        namespace marshalling {
            namespace types {
                /*********************** Plonk constraint ****************************/
                template<typename TTypeBase, typename PlonkConstraint>
                using plonk_constraint = typename expression<TTypeBase, typename PlonkConstraint::base_type>::type;

                template<typename Endianness, typename PlonkConstraint>
                plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint>
                fill_plonk_constraint(const PlonkConstraint &constr) {
                    return fill_expression<typename PlonkConstraint::base_type, Endianness>(constr);
                }

                template<typename Endianness, typename PlonkConstraint>
                PlonkConstraint make_plonk_constraint(
                    const plonk_constraint<nil::marshalling::field_type<Endianness>, PlonkConstraint> &filled_constr
                ) {
                    return make_expression<typename PlonkConstraint::base_type, Endianness>(filled_constr);
                }

                /*********************** Vector of plonk constraints as an input to gate ****************************/
                template<typename TTypeBase, typename Constraint>
                using plonk_constraints = nil::marshalling::types::array_list<
                    TTypeBase,
                    plonk_constraint<TTypeBase, Constraint>,
                    nil::marshalling::option::sequence_size_field_prefix<nil::marshalling::types::integral<TTypeBase, std::size_t>>
                >;

                template<typename Endianness, typename Constraint>
                plonk_constraints<nil::marshalling::field_type<Endianness>, Constraint>
                fill_plonk_constraints(const std::vector<Constraint> &constraints) {
                    using TTypeBase = nil::marshalling::field_type<Endianness>;

                    plonk_constraints<TTypeBase, Constraint> filled_constraints;
                    for (const auto &constraint : constraints) {
                        filled_constraints.value().push_back(fill_plonk_constraint<Endianness, Constraint>(constraint));
                    }

                    return filled_constraints;
                }

                template<typename Endianness, typename Constraint>
                std::vector<Constraint>
                make_plonk_constraints(const plonk_constraints<nil::marshalling::field_type<Endianness>, Constraint> &filled_constraints){
                    std::vector<Constraint> constraints;
                    for (std::size_t i = 0; i < filled_constraints.value().size(); i++) {
                        constraints.emplace_back(make_plonk_constraint<Endianness, Constraint>(filled_constraints.value().at(i)));
                    }
                    return constraints;
                }
            }    // namespace types
        }        // namespace marshalling
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_MARSHALLING_ZK_PLONK_CONSTRAINT_HPP
