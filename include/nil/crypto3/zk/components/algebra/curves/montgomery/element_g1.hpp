//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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
// @file Declaration of interfaces for G1 components.
//
// The components verify curve arithmetic in G1 = E(F) where E/F: b * y^2 = x^3 + a * x^2 + x
// is an elliptic curve over F in Montgomery form.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_MONTGOMERY_G1_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_MONTGOMERY_G1_COMPONENT_HPP

#include <nil/crypto3/zk/components/algebra/curves/element_g1_affine.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                /**
                 * @brief Component that creates constraints for the addition of two elements from G1. (if element from group G1 lies on the elliptic curve)
                 */
                template<typename Curve>
                struct element_g1_addition<Curve,
                                           algebra::curves::forms::montgomery,
                                           algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve,
                                                           algebra::curves::forms::montgomery,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::montgomery;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    element_component p1;
                    element_component p2;
                    element_component result;
                    element_fp<field_type> lambda;

                    element_g1_addition(blueprint<field_type> &bp,
                                        const element_component &in_p1,
                                        const element_component &in_p2) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), result(bp) {
                        blueprint_variable<field_type> lambda_var;
                        lambda_var.allocate(this->bp);
                        this->lambda = lambda_var;
                    }

                    void generate_r1cs_constraints() {
                        // lambda = (y' - y) / (x' - x)
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({p2.X - p1.X}, {lambda}, {p2.Y - p1.Y}));
                        // (lambda) * (lambda) = (A + x + x' + x'')
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {lambda}, {lambda}, {group_type::params_type::A + p1.X + p2.X + result.X}));
                        // y'' = -(y + lambda(x'' - x))
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({p1.X - result.X}, lambda, {result.Y + p1.Y}));
                    }

                    void generate_r1cs_witness() {
                        this->bp.lc_val(lambda) = (this->bp.lc_val(p2.Y) - this->bp.lc_val(p1.Y)) *
                                                  (this->bp.lc_val(p2.X) - this->bp.lc_val(p1.X)).inversed();
                        this->bp.lc_val(result.X) = this->bp.lc_val(lambda).squared() -
                                                    curve_type::template g1_type<coordinates, form>::params_type::A -
                                                    this->bp.lc_val(p1.X) - this->bp.lc_val(p2.X);
                        this->bp.lc_val(result.Y) =
                            -(this->bp.lc_val(p1.Y) +
                              (this->bp.lc_val(lambda) * (this->bp.lc_val(result.X) - this->bp.lc_val(p1.X))));
                    }
                };

                // /**
                //  * Gadget to verify the conversion between the Montgomery form of a point and its twisted Edwards
                //  form.
                //  */
                // template<typename Curve>
                // struct element_g1_to_edwards<Curve,
                //                             algebra::curves::forms::montgomery,
                //                             algebra::curves::coordinates::affine>
                //     : public component<typename element_g1<Curve,
                //                                            algebra::curves::forms::montgomery,
                //                                            algebra::curves::coordinates::affine>::field_type> {
                //     using curve_type = Curve;
                //     using form = algebra::curves::forms::montgomery;
                //     using coordinates = algebra::curves::coordinates::affine;
                //
                //     using element_component = element_g1<curve_type, form, coordinates>;
                //
                //     using field_type = typename element_component::field_type;
                //     using group_type = typename element_component::group_type;
                //
                //     // Input point
                //     element_g1<curve_type, representation_type> P_montgomery;
                //
                //     // Output point
                //     element_g1<curve_type, algebra::curves::representations::edwards> P_edwards;
                //
                //     element_g1_montgomery_to_edwards(blueprint<field_type> &bp,
                //                                      element_g1<curve_type, representation_type>
                //                                          P_montgomery,
                //                                      element_g1<curve_type,
                //                                      algebra::curves::representations::edwards>
                //                                          P_edwards) :
                //         detail::basic_element_g1_operation<curve_type, representation_type>(bp),
                //         P_montgomery(P_montgomery), P_edwards(P_edwards) {
                //     }
                //
                //     void generate_r1cs_constraints() {
                //         this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                //             {P_montgomery.Y}, {P_edwards.X}, {P_montgomery.X * this->field_element_scale}));
                //         this->bp.add_r1cs_constraint(
                //             snark::r1cs_constraint<field_type>({P_montgomery.X + field_type::value_type::one()},
                //                                                {P_edwards.Y},
                //                                                {P_montgomery.X - field_type::value_type::one()}));
                //     }
                //     void generate_r1cs_witness() {
                //         this->bp.lc_val(P_edwards.X) = this->field_element_scale * this->bp.lc_val(P_montgomery.X) *
                //                                        this->bp.lc_val(P_montgomery.Y).inversed();
                //         this->bp.lc_val(P_edwards.Y) =
                //             (this->bp.lc_val(P_montgomery.X) - field_type::value_type::one()) *
                //             (this->bp.lc_val(P_montgomery.X) + field_type::value_type::one()).inversed();
                //     }
                // };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MONTGOMERY_G1_COMPONENT_HPP