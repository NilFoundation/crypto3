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

#define BOOST_TEST_MODULE blueprint_fixed_base_mul_zcash_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/components/algebra/curves/montgomery/element_g1.hpp>
#include <nil/crypto3/zk/components/algebra/curves/twisted_edwards/element_g1.hpp>
#include <nil/crypto3/zk/components/algebra/curves/fixed_base_mul_zcash.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

template<typename Curve>
void test_curves_g1_fixed_base_mul_zcash_component(
    components::blueprint<typename Curve::base_field_type> &bp,
    components::blueprint_variable_vector<typename Curve::base_field_type> &in_bits,
    const typename Curve::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type
        &expected) {
    using curve_type = Curve;
    using fixed_base_mul_zcash_component = components::fixed_base_mul_zcash<curve_type>;
    using field_type = typename fixed_base_mul_zcash_component::field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;
    using twisted_edwards_group_value_type =
        typename fixed_base_mul_zcash_component::twisted_edwards_element_component::group_value_type;

    std::size_t basepoints_required = components::fixed_base_mul_zcash<curve_type>::basepoints_required(in_bits.size());
    std::vector<twisted_edwards_group_value_type> all_basepoints = {
        {field_value_type(
             integral_type("13418723823902222986275588345615650707197303761863176429873001977640541977977")),
         field_value_type(
             integral_type("15255921313433251341520743036334816584226787412845488772781699434149539664639"))},
        {field_value_type(
             integral_type("11749872627669176692285695179399857264465143297451429569602068921530882657945")),
         field_value_type(
             integral_type("2495745987765795949478491016197984302943511277003077751830848242972604164102"))}};
    for (const auto &p : all_basepoints) {
        BOOST_CHECK(p.is_well_formed());
    }

    std::vector<twisted_edwards_group_value_type> basepoints;
    std::copy(all_basepoints.begin(), all_basepoints.begin() + basepoints_required, std::back_inserter(basepoints));

    // components::element_g1<curve_type,
    //     representation_type> result(bp);

    fixed_base_mul_zcash_component fixed_base_mul_instance(bp, basepoints, in_bits);

    fixed_base_mul_instance.generate_r1cs_witness();
    fixed_base_mul_instance.generate_r1cs_constraints();

    BOOST_CHECK(expected.X == bp.lc_val(fixed_base_mul_instance.result().X));
    BOOST_CHECK(expected.Y == bp.lc_val(fixed_base_mul_instance.result().Y));
    BOOST_CHECK(bp.is_satisfied());
}

template<typename Curve>
static void test_curves_g1_fixed_base_mul_zcash_component(
    const std::vector<bool> &bits,
    const typename Curve::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type
        &expected) {
    using curve_type = Curve;
    using fixed_base_mul_zcash_component = components::fixed_base_mul_zcash<curve_type>;
    using field_type = typename fixed_base_mul_zcash_component::field_type;

    components::blueprint<field_type> bp;
    components::blueprint_variable_vector<field_type> scalar;
    scalar.allocate(bp, bits.size());
    scalar.fill_with_bits(bp, bits);

    test_curves_g1_fixed_base_mul_zcash_component<Curve>(bp, scalar, expected);
}

template<typename Curve>
static void test_curves_g1_fixed_base_mul_zcash_component(
    const typename Curve::base_field_type::value_type &s,
    std::size_t size,
    const typename Curve::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type
        &expected) {
    // Because one of test has different size (the on with 255)
    // std::size_t size = multiprecision::msb(integral_type(s.data)) + 1;
    using curve_type = Curve;
    using fixed_base_mul_zcash_component = components::fixed_base_mul_zcash<curve_type>;
    using field_type = typename fixed_base_mul_zcash_component::field_type;

    components::blueprint<field_type> bp;
    components::blueprint_variable_vector<field_type> scalar;
    scalar.allocate(bp, size);
    scalar.fill_with_bits_of_field_element(bp, s);

    test_curves_g1_fixed_base_mul_zcash_component<Curve>(bp, scalar, expected);
}

BOOST_AUTO_TEST_SUITE(blueprint_fixed_base_mul_zcash_manual_test_suite)

// BOOST_AUTO_TEST_CASE(edwards_fixed_base_mul_zcash_jubjub_test) {

//     using curve_type = curves::jubjub;

//     std::cout << "Edwards curve fixed_base_mul_zcash component test started" << std::endl;
//     typename curve_type::g1_type::value_type p1 =
//         random_element<typename curve_type::g1_type>();
//     std::cout << "Started for JubJub" << std::endl;
//     test_curves_g1_fixed_base_mul_zcash_component<curve_type,
//         algebra::curves::representations::edwards>(p1);
// }

BOOST_AUTO_TEST_CASE(babyjubjub_test) {

    using curve_type = curves::babyjubjub;
    using field_type = typename curve_type::base_field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;

    std::cout << "Edwards curve fixed_base_mul_zcash component fields test started" << std::endl;
    // typename curve_type::g1_type::value_type p1 =
    //     random_element<typename curve_type::g1_type>();
    std::cout << "Started for BabyJubJub" << std::endl;

    field_value_type scalar =
        field_value_type(integral_type("6453482891510615431577168724743356132495662554103773572771861111634748265227"));
    auto expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("6545697115159207040330446958704617656199928059562637738348733874272425400594")),
            field_value_type(
                integral_type("16414097465381367987194277536478439232201417933379523927469515207544654431390")));

    test_curves_g1_fixed_base_mul_zcash_component<curve_type>(scalar, 252, expected);

    scalar = field_value_type(integral_type("267"));
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("6790798216812059804926342266703617627640027902964190490794793207272357201212")),
            field_value_type(
                integral_type("2522797517250455013248440571887865304858084343310097011302610004060289809689")));

    test_curves_g1_fixed_base_mul_zcash_component<curve_type>(scalar, 9, expected);

    scalar = field_value_type(
        integral_type("21888242871839275222246405745257275088548364400416034343698204186575808495616"));
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("16322787121012335146141962340685388833598805940095898416175167744309692564601")),
            field_value_type(
                integral_type("7671892447502767424995649701270280747270481283542925053047237428072257876309")));

    test_curves_g1_fixed_base_mul_zcash_component<curve_type>(scalar, 255, expected);
}

// BOOST_AUTO_TEST_CASE(edwards_fixed_base_mul_zcash_babyjubjub_bytes_test) {

//     using curve_type = curves::babyjubjub;
//     using field_type = typename curve_type::base_field_type;
//     using field_value_type = typename field_type::value_type;
//     using integral_type = typename field_type::integral_type;
//     using value_type = typename curve_type::g1_type::value_type;

//     std::cout << "Edwards curve fixed_base_mul_zcash component bytes test started" << std::endl;
//     // typename curve_type::g1_type::value_type p1 =
//     //     random_element<typename curve_type::g1_type>();
//     std::cout << "Started for BabyJubJub" << std::endl;

//     auto bits = bytes_to_bv((const uint8_t*)"abc", 3);

//     typename curve_type::g1_type::value_type expected =
//         typename curve_type::g1_type::value_type (
//             field_value_type(integral_type("9869277320722751484529016080276887338184240285836102740267608137843906399765")),
//             field_value_type(integral_type("19790690237145851554496394080496962351633528315779989340140084430077208474328"))
//     );

//     test_curves_g1_fixed_base_mul_zcash_component<curve_type,
//         algebra::curves::representations::edwards>(bits,
//             expected);

//     bits = bytes_to_bv((const uint8_t*)"abcdef", 6);

//     expected =
//         typename curve_type::g1_type::value_type (
//             field_value_type(integral_type("3152592107782913127811973383449327981421816164636305446433885391611437772003")),
//             field_value_type(integral_type("21757413191206167432148830329017031919270024158827230996476733729375089049175"))
//     );

//     test_curves_g1_fixed_base_mul_zcash_component<curve_type,
//         algebra::curves::representations::edwards>(bits,
//             expected);

//     bits = bytes_to_bv((const uint8_t*)"abcdefghijklmnopqrstuvwx", 24);

//     expected =
//         typename curve_type::g1_type::value_type (
//             field_value_type(integral_type("3966548799068703226441887746390766667253943354008248106643296790753369303077")),
//             field_value_type(integral_type("12849086395963202120677663823933219043387904870880733726805962981354278512988"))
//     );

//     test_curves_g1_fixed_base_mul_zcash_component<curve_type,
//         algebra::curves::representations::edwards>(bits,
//             expected);

// }

BOOST_AUTO_TEST_SUITE_END()