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
// @file Declaration of affine G1 element component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_G1_AFFINE_COMPONENT_HPP
#define CRYPTO3_ZK_BLUEPRINT_G1_AFFINE_COMPONENT_HPP

#include <nil/crypto3/zk/component.hpp>
#include <nil/crypto3/zk/components/algebra/fields/element_fp.hpp>
#include <nil/crypto3/zk/components/algebra/curves/element_ops.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/montgomery/coordinates.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/twisted_edwards/coordinates.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {
                template<typename Curve, typename Form, typename Coordinates>
                struct element_g1;

                /**
                 * @brief Component that represents a G1 element in affine coordinates.
                 */
                template<typename Curve, typename Form>
                struct element_g1<Curve, Form, algebra::curves::coordinates::affine>
                    : public component<typename Curve::base_field_type> {
                    using curve_type = Curve;
                    using form = Form;
                    using coordinates = algebra::curves::coordinates::affine;
                    using group_type = typename curve_type::template g1_type<coordinates, form>;
                    using field_type = typename curve_type::base_field_type;
                    using group_value_type = typename group_type::value_type;
                    using field_value_type = typename field_type::value_type;

                    using underlying_element_type = algebra::fields::detail::element_fp<field_type>;

                    using addition_component = element_g1_addition<curve_type, form, coordinates>;
                    using is_well_formed_component = element_g1_is_well_formed<curve_type, form, coordinates>;
                    using to_twisted_edwards_component = element_g1_to_twisted_edwards<curve_type, form, coordinates>;
                    using to_bits_component = element_g1_to_bits<curve_type, form, coordinates>;

                    underlying_element_type X;
                    underlying_element_type Y;

                    element_g1(blueprint<field_type> &bp) : component<field_type>(bp) {
                        detail::blueprint_variable<field_type> X_var, Y_var;

                        X_var.allocate(bp);
                        Y_var.allocate(bp);

                        X = X_var;
                        Y = Y_var;
                    }

                    element_g1(blueprint<field_type> &bp, const group_value_type &p) : element_g1(bp) {
                        bp.lc_val(X) = p.X.data;
                        bp.lc_val(Y) = p.Y.data;
                    }

                    element_g1(blueprint<field_type> &bp, const underlying_element_type &in_X,
                               const underlying_element_type &in_Y) :
                        component<field_type>(bp),
                        X(in_X), Y(in_Y) {
                    }

                    // TODO: maybe add is_well_formed constraints
                    void generate_r1cs_constraints() {
                    }

                    void generate_r1cs_witness(const group_value_type &p) {
                        this->bp.lc_val(X) = p.X.data;
                        this->bp.lc_val(Y) = p.Y.data;
                    }

                    // (See a comment in r1cs_ppzksnark_verifier_component.hpp about why
                    // we mark this function noinline.) TODO: remove later
                    static std::size_t BOOST_NOINLINE size_in_bits() {
                        return 2 * field_type::modulus_bits;    // This probably should be value_bits, not
                                                                // modulus_bits
                    }

                    static std::size_t num_variables() {
                        return 2;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_G1_AFFINE_COMPONENT_HPP