//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/math/polynomial/shift.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

#include <nil/crypto3/zk/snark/relations/variable.hpp>
#include <nil/crypto3/zk/snark/relations/non_linear_combination.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace snark {

                /************************* PLONK constraint ***********************************/

                template<typename FieldType>
                using plonk_constraint = non_linear_combination<FieldType, true>;

                /************************* PLONK variable assignment **************************/

                template<typename FieldType, std::size_t WiresAmount>
                using plonk_variable_assignment = std::array<std::vector<typename FieldType::value_type>, WiresAmount>;

                /************************* PLONK constraint system ****************************/

                template<typename FieldType, std::size_t WiresAmount>
                struct plonk_constraint_system {

                    std::vector<plonk_constraint<FieldType>> constraints;

                    plonk_constraint_system() {
                    }

                    constexpr std::size_t num_wires() const {
                        return WiresAmount;
                    }

                    std::size_t num_constraints() const {
                        return constraints.size();
                    }

                    bool
                        is_satisfied(plonk_variable_assignment<FieldType, WiresAmount> full_variable_assignment) const {

                        for (std::size_t c = 0; c < constraints.size(); ++c) {
                            if (!constraints[c].a.evaluate(full_variable_assignment).is_zero()) {
                                return false;
                            }
                        }

                        return true;
                    }

                    std::vector<math::polynomial<typename FieldType::value_type>> copy_constraints() {
                        return {};
                    }

                    std::vector<math::polynomial<typename FieldType::value_type>> selectors() {
                        return {};
                    }

                    std::vector<math::polynomial<typename FieldType::value_type>> lookups() {
                        return {};
                    }

                    std::vector<math::polynomial<typename FieldType::value_type>>
                        polynomials(plonk_variable_assignment<FieldType, WiresAmount> full_variable_assignment) const {

                        std::vector<math::polynomial<typename FieldType::value_type>> result(constraints.size());

                        std::array<math::polynomial<typename FieldType::value_type>, WiresAmount> wire_polynomials;
                        for (std::size_t wire_index = 0; wire_index < WiresAmount; wire_index++) {
                            const std::shared_ptr<math::evaluation_domain<FieldType>> domain =
                                math::make_evaluation_domain<FieldType>(full_variable_assignment[wire_index].size());

                            std::vector<typename FieldType::value_type> interpolation_points(
                                full_variable_assignment[wire_index].size());

                            std::copy(full_variable_assignment[wire_index].begin(),
                                      full_variable_assignment[wire_index].end(), interpolation_points.begin());

                            domain->inverse_fft(interpolation_points);

                            wire_polynomials[wire_index] =
                                math::polynomial<typename FieldType::value_type>(interpolation_points);
                        }

                        for (std::size_t constraint_index = 0; constraint_index < constraints.size();
                             constraint_index++) {

                            for (auto &term : constraints[constraint_index].terms) {

                                math::polynomial<typename FieldType::value_type> term_polynom = {term.coeff};

                                for (auto &var : term.vars) {
                                    term_polynom =
                                        term_polynom * math::polynomial_shift(wire_polynomials[var.wire_index],
                                                                              domain->get_domain_element(var.rotation));
                                }

                                result[constraint_index] = result[constraint_index] + term_polynom;
                            }
                        }

                        return result;
                    }

                    void add_constraint(const plonk_constraint<FieldType> &c) {
                        constraints.emplace_back(c);
                    }

                    bool operator==(const plonk_constraint_system &other) const {
                        return (this->constraints == other.constraints);
                    }
                };
            }    // namespace snark
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_PLONK_CONSTRAINT_SYSTEM_HPP
