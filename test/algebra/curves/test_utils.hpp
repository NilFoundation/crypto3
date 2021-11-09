//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
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

#ifndef CRYPTO3_ZK_BLUEPRINT_CURVES_TEST_UTILS_HPP
#define CRYPTO3_ZK_BLUEPRINT_CURVES_TEST_UTILS_HPP

#include <nil/crypto3/zk/components/algebra/curves/element_g1_affine.hpp>

using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

enum : std::size_t {
    p1,
    p2,
    p1_plus_p2,
};

template<typename Curve, typename ElementComponent>
void check_input_points(const std::vector<typename ElementComponent::group_value_type> &points) {
    using curve_type = Curve;
    using element_component = ElementComponent;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    for (const auto &p : points) {
        BOOST_CHECK(p.is_well_formed());
    }
    BOOST_CHECK(points[p1] + points[p2] == points[p1_plus_p2]);
}

template<typename Curve, typename ElementComponent>
void check_addition_component(const std::vector<typename ElementComponent::group_value_type> &points) {
    using curve_type = Curve;
    using element_component = ElementComponent;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    components::blueprint<field_type> bp, bp_copy;
    element_component p1_component(bp, points[p1]);
    element_component p2_component(bp, points[p2]);
    element_component p1_plus_p2_component(bp, points[p1_plus_p2]);
    typename element_component::addition_component add_component(bp, p1_component, p2_component);

    add_component.generate_r1cs_witness();
    add_component.generate_r1cs_constraints();

    bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>({points[p1_plus_p2].X}, {field_type::value_type::one()},
                                                              {add_component.result.X}));
    bp_copy = bp;
    bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>({points[p1_plus_p2].Y}, {field_type::value_type::one()},
                                                              {add_component.result.Y}));
    BOOST_CHECK(bp.is_satisfied());
    bp_copy.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
        {points[p1_plus_p2].Y}, {-field_type::value_type::one()}, {add_component.result.Y}));
    BOOST_CHECK(!bp_copy.is_satisfied());

    bp_copy = bp;
    bp_copy.add_r1cs_constraint(snark::r1cs_constraint<field_type>(
        {-(points[p1_plus_p2].Y)}, {field_type::value_type::one()}, {add_component.result.Y}));
    BOOST_CHECK(!bp_copy.is_satisfied());
}

template<typename Curve, typename ElementComponent>
void check_is_well_formed_component(const std::vector<typename ElementComponent::group_value_type> &points) {
    using curve_type = Curve;
    using element_component = ElementComponent;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    for (const auto &p : points) {
        components::blueprint<field_type> bp, bp_copy;
        element_component p_component(bp, p);
        typename element_component::is_well_formed_component is_well_component(bp, p_component);
        is_well_component.generate_r1cs_witness();
        is_well_component.generate_r1cs_constraints();
        BOOST_CHECK(bp.is_satisfied());

        // point is not on the curve
        auto p_copy = p;
        // TODO: set random field element would be better
        p_copy.X = field_type::value_type::zero();
        element_component p_component_copy(bp_copy, p_copy);
        typename element_component::is_well_formed_component is_well_component_copy(bp_copy, p_component_copy);
        is_well_component_copy.generate_r1cs_witness();
        is_well_component_copy.generate_r1cs_constraints();
        BOOST_CHECK(!bp_copy.is_satisfied());
    }
}

template<typename Curve, typename ElementComponent =
                             components::element_g1<Curve, curves::forms::montgomery, curves::coordinates::affine>>
void check_affine_montgomery_g1_operations(const std::vector<typename ElementComponent::group_value_type> &points) {
    check_input_points<Curve, ElementComponent>(points);
    check_addition_component<Curve, ElementComponent>(points);
}

template<typename Curve, typename ElementComponent =
                             components::element_g1<Curve, curves::forms::twisted_edwards, curves::coordinates::affine>>
void check_affine_twisted_edwards_g1_operations(
    const std::vector<typename ElementComponent::group_value_type> &points) {
    check_input_points<Curve, ElementComponent>(points);
    check_addition_component<Curve, ElementComponent>(points);
    check_is_well_formed_component<Curve, ElementComponent>(points);
}

#endif    // CRYPTO3_ZK_BLUEPRINT_CURVES_TEST_UTILS_HPP
