//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for G1 components.
//
// The components verify curve arithmetic in G1 = E(F) where E/F: y^2 = x^3 + A * X + B
// is an elliptic curve over F in short Weierstrass form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP

#include <nil/crypto3/zk/components/component.hpp>

#include <nil/crypto3/zk/components/blueprint_variable.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename CurveType>
                class element_g1;

                template<typename CurveType>
                class element_g1_add;

                template<typename CurveType>
                class element_g1_doubled;

                /**
                 * Component that creates constraints for G1 multi-scalar multiplication.
                 */
                template<typename CurveType>
                class scalar_mul : public component<typename CurveType::scalar_field_type> {
                    typedef typename CurveType::scalar_field_type FieldType;

                public:
                    std::vector<element_g1<CurveType>> computed_results;
                    std::vector<element_g1<CurveType>> chosen_results;
                    std::vector<element_g1_add<CurveType>> adders;
                    std::vector<element_g1_doubled<CurveType>> doublers;

                    element_g1<CurveType> base;
                    blueprint_variable_vector<FieldType> scalars;
                    std::vector<element_g1<CurveType>> points;
                    std::vector<element_g1<CurveType>> points_and_powers;
                    element_g1<CurveType> result;

                    const std::size_t elt_size;
                    const std::size_t num_points;
                    const std::size_t scalar_size;

                    scalar_mul(blueprint<FieldType> &bp,
                               const element_g1<CurveType> &base,
                               const blueprint_variable_vector<FieldType> &scalars,
                               const std::size_t elt_size,
                               const std::vector<element_g1<CurveType>> &points,
                               const element_g1<CurveType> &result) :
                        component<FieldType>(bp),
                        base(base), scalars(scalars), points(points), result(result), elt_size(elt_size),
                        num_points(points.size()), scalar_size(scalars.size()) {

                        assert(num_points >= 1);
                        assert(num_points * elt_size == scalar_size);

                        for (std::size_t i = 0; i < num_points; ++i) {
                            points_and_powers.emplace_back(points[i]);
                            for (std::size_t j = 0; j < elt_size - 1; ++j) {
                                points_and_powers.emplace_back(element_g1<CurveType>(bp));
                                doublers.emplace_back(element_g1_doubled<CurveType>(
                                    bp, points_and_powers[i * elt_size + j], points_and_powers[i * elt_size + j + 1]));
                            }
                        }

                        chosen_results.emplace_back(base);
                        for (std::size_t i = 0; i < scalar_size; ++i) {
                            computed_results.emplace_back(element_g1<CurveType>(bp));
                            if (i < scalar_size - 1) {
                                chosen_results.emplace_back(element_g1<CurveType>(bp));
                            } else {
                                chosen_results.emplace_back(result);
                            }

                            adders.emplace_back(element_g1_add<CurveType>(
                                bp, chosen_results[i], points_and_powers[i], computed_results[i]));
                        }
                    }

                    void generate_r1cs_constraints() {
                        const std::size_t num_constraints_before = this->bp.num_constraints();

                        for (std::size_t i = 0; i < scalar_size - num_points; ++i) {
                            doublers[i].generate_r1cs_constraints();
                        }

                        for (std::size_t i = 0; i < scalar_size; ++i) {
                            adders[i].generate_r1cs_constraints();

                            /*
                              chosen_results[i+1].X = scalars[i] * computed_results[i].X + (1-scalars[i]) *
                              chosen_results[i].X chosen_results[i+1].X - chosen_results[i].X = scalars[i] *
                              (computed_results[i].X - chosen_results[i].X)
                            */
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<FieldType>(scalars[i],
                                                                  computed_results[i].X - chosen_results[i].X,
                                                                  chosen_results[i + 1].X - chosen_results[i].X));
                            this->bp.add_r1cs_constraint(
                                snark::r1cs_constraint<FieldType>(scalars[i],
                                                                  computed_results[i].Y - chosen_results[i].Y,
                                                                  chosen_results[i + 1].Y - chosen_results[i].Y));
                        }

                        const std::size_t num_constraints_after = this->bp.num_constraints();
                        assert(num_constraints_after - num_constraints_before ==
                               4 * (scalar_size - num_points) + (4 + 2) * scalar_size);
                    }

                    void generate_r1cs_witness() {
                        for (std::size_t i = 0; i < scalar_size - num_points; ++i) {
                            doublers[i].generate_r1cs_witness();
                        }

                        for (std::size_t i = 0; i < scalar_size; ++i) {
                            adders[i].generate_r1cs_witness();
                            this->bp.lc_val(chosen_results[i + 1].X) =
                                (this->bp.val(scalars[i]) == typename CurveType::scalar_field_type::value_type::zero() ?
                                     this->bp.lc_val(chosen_results[i].X) :
                                     this->bp.lc_val(computed_results[i].X));
                            this->bp.lc_val(chosen_results[i + 1].Y) =
                                (this->bp.val(scalars[i]) == typename CurveType::scalar_field_type::value_type::zero() ?
                                     this->bp.lc_val(chosen_results[i].Y) :
                                     this->bp.lc_val(computed_results[i].Y));
                        }
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_WEIERSTRASS_G1_COMPONENT_HPP
