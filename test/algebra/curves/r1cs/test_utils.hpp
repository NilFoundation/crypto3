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

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_CURVES_TEST_UTILS_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_CURVES_TEST_UTILS_HPP

#include <vector>

#include <boost/iterator/zip_iterator.hpp>
#include <boost/tuple/tuple.hpp>

#include <nil/blueprint/components/algebra/curves/element_g1_affine.hpp>

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
void check_addition_component_auto_allocation(const std::vector<typename ElementComponent::group_value_type> &points) {
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

    add_component.generate_assignments();
    add_component.generate_gates();

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
void check_addition_component_manual_allocation(
    const std::vector<typename ElementComponent::group_value_type> &points) {
    using curve_type = Curve;
    using element_component = ElementComponent;
    using field_type = typename element_component::field_type;
    using integral_type = typename field_type::integral_type;
    using group_value_type = typename element_component::group_value_type;

    components::blueprint<field_type> bp, bp_copy;
    element_component p1_component(bp, points[p1]);
    element_component p2_component(bp, points[p2]);
    element_component result(bp);
    // element_component p1_plus_p2_component(bp, points[p1_plus_p2]);
    typename element_component::addition_component add_component(bp, p1_component, p2_component, result);

    add_component.generate_assignments();
    add_component.generate_gates();
    BOOST_CHECK(bp.is_satisfied());

    bp.add_r1cs_constraint(
        snark::r1cs_constraint<field_type>({points[p1_plus_p2].X}, {field_type::value_type::one()}, {result.X}));
    bp_copy = bp;
    bp.add_r1cs_constraint(
        snark::r1cs_constraint<field_type>({points[p1_plus_p2].Y}, {field_type::value_type::one()}, {result.Y}));
    BOOST_CHECK(bp.is_satisfied());
    bp_copy.add_r1cs_constraint(
        snark::r1cs_constraint<field_type>({points[p1_plus_p2].Y}, {-field_type::value_type::one()}, {result.Y}));
    BOOST_CHECK(!bp_copy.is_satisfied());

    bp_copy = bp;
    bp_copy.add_r1cs_constraint(
        snark::r1cs_constraint<field_type>({-(points[p1_plus_p2].Y)}, {field_type::value_type::one()}, {result.Y}));
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
        is_well_component.generate_assignments();
        is_well_component.generate_gates();
        BOOST_CHECK(bp.is_satisfied());

        // point is not on the curve
        auto p_copy = p;
        // TODO: set random field element would be better
        p_copy.X = field_type::value_type::zero();
        element_component p_component_copy(bp_copy, p_copy);
        typename element_component::is_well_formed_component is_well_component_copy(bp_copy, p_component_copy);
        is_well_component_copy.generate_assignments();
        is_well_component_copy.generate_gates();
        BOOST_CHECK(!bp_copy.is_satisfied());
    }
}

template<
    typename Curve,
    typename FromElementComponent =
        components::element_g1<Curve, curves::forms::montgomery, curves::coordinates::affine>,
    typename ToElementComponent = typename FromElementComponent::to_twisted_edwards_component::to_element_component>
void check_montgomery_to_twisted_edwards_component_auto_allocation(
    const std::vector<typename FromElementComponent::group_value_type> &points_from,
    const std::vector<typename ToElementComponent::group_value_type> &points_to) {
    using curve_type = Curve;
    using field_type = typename FromElementComponent::field_type;

    assert(points_from.size() == points_to.size());
    check_input_points<Curve, FromElementComponent>(points_from);
    check_input_points<Curve, ToElementComponent>(points_to);

    // TODO: extend test to check wrong values
    std::for_each(boost::make_zip_iterator(boost::make_tuple(std::cbegin(points_from), std::cbegin(points_to))),
                  boost::make_zip_iterator(boost::make_tuple(std::cend(points_from), std::cend(points_to))),
                  [&](const boost::tuple<const typename FromElementComponent::group_value_type &,
                                         const typename ToElementComponent::group_value_type &> &t) {
                      components::blueprint<field_type> bp, bp_copy;
                      FromElementComponent p_component(bp, t.template get<0>());
                      typename FromElementComponent::to_twisted_edwards_component to_tw_edwards_component(bp,
                                                                                                          p_component);
                      to_tw_edwards_component.generate_assignments();
                      to_tw_edwards_component.generate_gates();

                      bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(t.template get<1>().X, 1,
                                                                                to_tw_edwards_component.result.X));
                      bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(t.template get<1>().Y, 1,
                                                                                to_tw_edwards_component.result.Y));

                      BOOST_CHECK(bp.is_satisfied());
                  });
}

template<
    typename Curve,
    typename FromElementComponent =
        components::element_g1<Curve, curves::forms::montgomery, curves::coordinates::affine>,
    typename ToElementComponent = typename FromElementComponent::to_twisted_edwards_component::to_element_component>
void check_montgomery_to_twisted_edwards_component_manual_allocation(
    const std::vector<typename FromElementComponent::group_value_type> &points_from,
    const std::vector<typename ToElementComponent::group_value_type> &points_to) {
    using curve_type = Curve;
    using field_type = typename FromElementComponent::field_type;

    assert(points_from.size() == points_to.size());
    check_input_points<Curve, FromElementComponent>(points_from);
    check_input_points<Curve, ToElementComponent>(points_to);

    // TODO: extend test to check wrong values
    std::for_each(boost::make_zip_iterator(boost::make_tuple(std::cbegin(points_from), std::cbegin(points_to))),
                  boost::make_zip_iterator(boost::make_tuple(std::cend(points_from), std::cend(points_to))),
                  [&](const boost::tuple<const typename FromElementComponent::group_value_type &,
                                         const typename ToElementComponent::group_value_type &> &t) {
                      components::blueprint<field_type> bp, bp_copy;
                      FromElementComponent p_component(bp, t.template get<0>());
                      ToElementComponent result(bp);
                      typename FromElementComponent::to_twisted_edwards_component to_tw_edwards_component(
                          bp, p_component, result);
                      to_tw_edwards_component.generate_assignments();
                      to_tw_edwards_component.generate_gates();

                      bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(t.template get<1>().X, 1, result.X));
                      bp.add_r1cs_constraint(snark::r1cs_constraint<field_type>(t.template get<1>().Y, 1, result.Y));

                      BOOST_CHECK(bp.is_satisfied());
                  });
}

template<
    typename Curve,
    typename FromElementComponent =
        components::element_g1<Curve, curves::forms::montgomery, curves::coordinates::affine>,
    typename ToElementComponent = typename FromElementComponent::to_twisted_edwards_component::to_element_component>
void check_montgomery_to_twisted_edwards_component(
    const std::vector<typename FromElementComponent::group_value_type> &points_from,
    const std::vector<typename ToElementComponent::group_value_type> &points_to) {
    check_montgomery_to_twisted_edwards_component_auto_allocation<Curve, FromElementComponent, ToElementComponent>(
        points_from, points_to);
    check_montgomery_to_twisted_edwards_component_manual_allocation<Curve, FromElementComponent, ToElementComponent>(
        points_from, points_to);
}

template<typename Curve, typename ElementComponent =
                             components::element_g1<Curve, curves::forms::montgomery, curves::coordinates::affine>>
void check_affine_montgomery_g1_operations(const std::vector<typename ElementComponent::group_value_type> &points) {
    check_input_points<Curve, ElementComponent>(points);
    check_addition_component_auto_allocation<Curve, ElementComponent>(points);
    check_addition_component_manual_allocation<Curve, ElementComponent>(points);
}

template<typename Curve, typename ElementComponent =
                             components::element_g1<Curve, curves::forms::twisted_edwards, curves::coordinates::affine>>
void check_affine_twisted_edwards_g1_operations(
    const std::vector<typename ElementComponent::group_value_type> &points) {
    check_input_points<Curve, ElementComponent>(points);
    check_addition_component_auto_allocation<Curve, ElementComponent>(points);
    check_addition_component_manual_allocation<Curve, ElementComponent>(points);
    check_is_well_formed_component<Curve, ElementComponent>(points);
}

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_CURVES_TEST_UTILS_HPP
