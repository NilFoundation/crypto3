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
                 * @brief Component that creates constraints for the addition of two elements from G1. (if element from
                 * group G1 lies on the elliptic curve)
                 */
                template<typename Curve>
                struct element_g1_addition<Curve, algebra::curves::forms::montgomery,
                                           algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve, algebra::curves::forms::montgomery,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::montgomery;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;

                    using result_type = element_component;

                    const element_component p1;
                    const element_component p2;
                    element_component result;
                    element_fp<field_type> lambda;

                    /// Auto allocation of the result
                    element_g1_addition(blueprint<field_type> &bp,
                                        const element_component &in_p1,
                                        const element_component &in_p2) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), result(bp) {
                        detail::blueprint_variable<field_type> lambda_var;
                        lambda_var.allocate(this->bp);
                        this->lambda = lambda_var;
                    }

                    /// Manual allocation of the result
                    element_g1_addition(blueprint<field_type> &bp,
                                        const element_component &in_p1,
                                        const element_component &in_p2,
                                        const result_type &in_result) :
                        component<field_type>(bp),
                        p1(in_p1), p2(in_p2), result(in_result) {
                        detail::blueprint_variable<field_type> lambda_var;
                        lambda_var.allocate(this->bp);
                        this->lambda = lambda_var;
                    }

                    void generate_r1cs_constraints() {
                        // lambda = (y' - y) / (x' - x)
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->p2.X - this->p1.X}, {this->lambda}, {this->p2.Y - this->p1.Y}));
                        // (lambda) * (lambda) = (A + x + x' + x'')
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->lambda},
                            {this->lambda},
                            {group_type::params_type::A + this->p1.X + this->p2.X + this->result.X}));
                        // y'' = -(y + lambda(x'' - x))
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
                            {this->p1.X - this->result.X}, this->lambda, {this->result.Y + this->p1.Y}));
                    }

                    void generate_r1cs_witness() {
                        this->bp.lc_val(this->lambda) =
                            (this->bp.lc_val(this->p2.Y) - this->bp.lc_val(this->p1.Y)) *
                            (this->bp.lc_val(this->p2.X) - this->bp.lc_val(this->p1.X)).inversed();
                        this->bp.lc_val(this->result.X) = this->bp.lc_val(this->lambda).squared() -
                                                          group_type::params_type::A - this->bp.lc_val(this->p1.X) -
                                                          this->bp.lc_val(this->p2.X);
                        this->bp.lc_val(this->result.Y) =
                            -(this->bp.lc_val(this->p1.Y) +
                              (this->bp.lc_val(this->lambda) *
                               (this->bp.lc_val(this->result.X) - this->bp.lc_val(this->p1.X))));
                    }
                };

                /**
                 * Gadget to convert affine Montgomery coordinates into affine twisted Edwards coordinates.
                 */
                template<typename Curve>
                struct element_g1_to_twisted_edwards<Curve, algebra::curves::forms::montgomery,
                                                     algebra::curves::coordinates::affine>
                    : public component<typename element_g1<Curve, algebra::curves::forms::montgomery,
                                                           algebra::curves::coordinates::affine>::field_type> {
                    using curve_type = Curve;
                    using form = algebra::curves::forms::montgomery;
                    using coordinates = algebra::curves::coordinates::affine;

                    using element_component = element_g1<curve_type, form, coordinates>;
                    using to_element_component =
                        element_g1<curve_type, algebra::curves::forms::twisted_edwards, coordinates>;

                    using field_type = typename element_component::field_type;
                    using group_type = typename element_component::group_type;
                    using to_group_type = typename to_element_component::group_type;

                    using result_type = to_element_component;

                    // Input point
                    const element_component p;
                    // Output point
                    result_type result;
                    // Intermediate variables
                    typename field_type::value_type scale;

                    /// Auto allocation of the result
                    element_g1_to_twisted_edwards(blueprint<field_type> &bp, const element_component &in_p) :
                        component<field_type>(bp), p(in_p), result(bp),
                        scale((static_cast<typename field_type::value_type>(4) /
                               (static_cast<typename field_type::value_type>(to_group_type::params_type::a) -
                                static_cast<typename field_type::value_type>(to_group_type::params_type::d)) /
                               static_cast<typename field_type::value_type>(group_type::params_type::B))
                                  .sqrt()) {
                    }

                    /// Manual allocation of the result
                    element_g1_to_twisted_edwards(blueprint<field_type> &bp, const element_component &in_p,
                                                  const result_type &in_result) :
                        component<field_type>(bp),
                        p(in_p), result(in_result),
                        scale((static_cast<typename field_type::value_type>(4) /
                               (static_cast<typename field_type::value_type>(to_group_type::params_type::a) -
                                static_cast<typename field_type::value_type>(to_group_type::params_type::d)) /
                               static_cast<typename field_type::value_type>(group_type::params_type::B))
                                  .sqrt()) {
                    }

                    void generate_r1cs_constraints() {
                        this->bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>({this->p.Y}, {this->result.X},
                                                                                        {this->p.X * this->scale}));
                        this->bp.add_r1cs_constraint(
                            snark::r1cs_constraint<field_type>({this->p.X + field_type::value_type::one()},
                                                               {this->result.Y},
                                                               {this->p.X - field_type::value_type::one()}));
                    }

                    void generate_r1cs_witness() {
                        typename to_group_type::value_type p_to_XY =
                            typename group_type::value_type(this->bp.lc_val(p.X), this->bp.lc_val(p.Y))
                                .to_twisted_edwards();
                        this->bp.lc_val(result.X) = p_to_XY.X;
                        this->bp.lc_val(result.Y) = p_to_XY.Y;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_MONTGOMERY_G1_COMPONENT_HPP
