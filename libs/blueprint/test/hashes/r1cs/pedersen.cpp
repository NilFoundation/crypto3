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

#define BOOST_TEST_MODULE blueprint_fixed_base_mul_zcash_component_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/blueprint/components/algebra/curves/montgomery/element_g1.hpp>
#include <nil/blueprint/components/algebra/curves/twisted_edwards/element_g1.hpp>
#include <nil/blueprint/components/hashes/pedersen.hpp>
#include <nil/blueprint/blueprint/r1cs/circuit.hpp>
#include <nil/blueprint/blueprint/r1cs/assignment.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::zk;
using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(std::ostream &os, const typename fields::detail::element_fp<FieldParams> &e) {
    std::cout << e.data << std::endl;
}

/// hashing to point
template<typename HashComponent, typename ExpectedType = typename HashComponent::result_type::group_value_type>
void test_blueprint_variable_vector_component_constructor(const std::vector<bool> &in_bits,
                                                          const ExpectedType &expected) {
    using field_type = typename HashComponent::field_type;

    // input as blueprint_variable_vector
    blueprint<field_type> bp, bp_manual;
    nil::crypto3::zk::detail::blueprint_variable_vector<field_type> scalar, scalar_manual;
    scalar.allocate(bp, in_bits.size());
    scalar.fill_with_bits(bp, in_bits);
    scalar_manual.allocate(bp_manual, in_bits.size());
    scalar_manual.fill_with_bits(bp_manual, in_bits);

    // Auto allocation of the result
    HashComponent hash_comp(bp, scalar);
    hash_comp.generate_assignments();
    hash_comp.generate_gates();
    BOOST_CHECK(expected.X == bp.lc_val(hash_comp.result.X));
    BOOST_CHECK(expected.Y == bp.lc_val(hash_comp.result.Y));
    BOOST_CHECK(bp.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_manual(bp_manual);
    HashComponent hash_comp_manual(bp_manual, scalar_manual, result_manual);
    hash_comp_manual.generate_assignments();
    hash_comp_manual.generate_gates();
    BOOST_CHECK(expected.X == bp_manual.lc_val(result_manual.X));
    BOOST_CHECK(expected.Y == bp_manual.lc_val(result_manual.Y));
    BOOST_CHECK(bp_manual.is_satisfied());

    std::cout << "Input bits: " << in_bits.size() << std::endl;
    std::cout << "To point constrains: " << bp.num_constraints() << std::endl;
}

/// hashing to point
template<typename HashComponent, typename ExpectedType = typename HashComponent::result_type::group_value_type>
void test_block_variable_component_constructor(const std::vector<bool> &in_bits, const ExpectedType &expected) {
    using field_type = typename HashComponent::field_type;

    // input as block_variable
    blueprint<field_type> bp, bp_manual;
    components::block_variable<field_type> in_block(bp, in_bits.size()), in_block_manual(bp_manual, in_bits.size());
    in_block.generate_assignments(in_bits);
    in_block_manual.generate_assignments(in_bits);

    // Auto allocation of the result
    HashComponent hash_comp(bp, in_block);
    hash_comp.generate_assignments();
    hash_comp.generate_gates();
    BOOST_CHECK(expected.X == bp.lc_val(hash_comp.result.X));
    BOOST_CHECK(expected.Y == bp.lc_val(hash_comp.result.Y));
    BOOST_CHECK(bp.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_manual(bp_manual);
    HashComponent hash_comp_manual(bp_manual, in_block_manual, result_manual);
    hash_comp_manual.generate_assignments();
    hash_comp_manual.generate_gates();
    BOOST_CHECK(expected.X == bp_manual.lc_val(result_manual.X));
    BOOST_CHECK(expected.Y == bp_manual.lc_val(result_manual.Y));
    BOOST_CHECK(bp_manual.is_satisfied());
}

/// hashing to point
template<typename HashComponent, typename ExpectedType = typename HashComponent::result_type::group_value_type>
void test_block_variables_component_constructor(const std::vector<bool> &in_bits, const ExpectedType &expected) {
    using field_type = typename HashComponent::field_type;

    // input as container of block_variable
    blueprint<field_type> bp, bp_manual;
    std::size_t half_size = in_bits.size() / 2;
    components::block_variable<field_type> in_block_left(bp, half_size), in_block_right(bp, in_bits.size() - half_size),
        in_block_manual_left(bp_manual, half_size), in_block_manual_right(bp_manual, in_bits.size() - half_size);
    in_block_left.generate_assignments(std::vector<bool>(std::cbegin(in_bits), std::cbegin(in_bits) + half_size));
    in_block_right.generate_assignments(std::vector<bool>(std::cbegin(in_bits) + half_size, std::cend(in_bits)));
    in_block_manual_left.generate_assignments(
        std::vector<bool>(std::cbegin(in_bits), std::cbegin(in_bits) + half_size));
    in_block_manual_right.generate_assignments(
        std::vector<bool>(std::cbegin(in_bits) + half_size, std::cend(in_bits)));

    // Auto allocation of the result
    HashComponent hash_comp(bp,
                            std::vector {
                                in_block_left,
                                in_block_right,
                            });
    hash_comp.generate_assignments();
    hash_comp.generate_gates();
    BOOST_CHECK(expected.X == bp.lc_val(hash_comp.result.X));
    BOOST_CHECK(expected.Y == bp.lc_val(hash_comp.result.Y));
    BOOST_CHECK(bp.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_manual(bp_manual);
    HashComponent hash_comp_manual(bp_manual,
                                   std::vector {
                                       in_block_manual_left,
                                       in_block_manual_right,
                                   },
                                   result_manual);
    hash_comp_manual.generate_assignments();
    hash_comp_manual.generate_gates();
    BOOST_CHECK(expected.X == bp_manual.lc_val(result_manual.X));
    BOOST_CHECK(expected.Y == bp_manual.lc_val(result_manual.Y));
    BOOST_CHECK(bp_manual.is_satisfied());
}

/// hashing to bits
template<typename HashComponent>
void test_blueprint_variable_vector_component_constructor(const std::vector<bool> &in_bits,
                                                          const std::vector<bool> &expected_bits) {
    using field_type = typename HashComponent::field_type;

    // input as blueprint_variable_vector
    blueprint<field_type> bp_bits, bp_bits_manual;
    nil::crypto3::zk::detail::blueprint_variable_vector<field_type> scalar_bits, scalar_bits_manual;
    scalar_bits.allocate(bp_bits, in_bits.size());
    scalar_bits.fill_with_bits(bp_bits, in_bits);
    scalar_bits_manual.allocate(bp_bits_manual, in_bits.size());
    scalar_bits_manual.fill_with_bits(bp_bits_manual, in_bits);

    // Auto allocation of the result
    HashComponent hash_comp_bits(bp_bits, scalar_bits);
    hash_comp_bits.generate_assignments();
    hash_comp_bits.generate_gates();
    BOOST_CHECK(expected_bits == hash_comp_bits.result.get_digest());
    BOOST_CHECK(bp_bits.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_bits_manual(bp_bits_manual, field_type::value_bits);
    HashComponent hash_comp_bits_manual(bp_bits_manual, scalar_bits_manual, result_bits_manual);
    hash_comp_bits_manual.generate_assignments();
    hash_comp_bits_manual.generate_gates();
    BOOST_CHECK(expected_bits == result_bits_manual.get_digest());
    BOOST_CHECK(bp_bits_manual.is_satisfied());

    std::cout << "Input bits: " << in_bits.size() << std::endl;
    std::cout << "To bits: " << bp_bits.num_constraints() << std::endl;
}

/// hashing to bits
template<typename HashComponent>
void test_digest_variable_component_constructor(const std::vector<bool> &in_bits,
                                                const std::vector<bool> &expected_bits) {
    using field_type = typename HashComponent::field_type;

    // input as digest_variable
    blueprint<field_type> bp_bits, bp_bits_manual;
    components::digest_variable<field_type> in_block(bp_bits, in_bits.size()),
        in_block_manual(bp_bits_manual, in_bits.size());
    in_block.generate_assignments(in_bits);
    in_block_manual.generate_assignments(in_bits);

    // Auto allocation of the result
    HashComponent hash_comp_bits(bp_bits, in_block);
    hash_comp_bits.generate_assignments();
    hash_comp_bits.generate_gates();
    BOOST_CHECK(expected_bits == hash_comp_bits.result.get_digest());
    BOOST_CHECK(bp_bits.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_bits_manual(bp_bits_manual, field_type::value_bits);
    HashComponent hash_comp_bits_manual(bp_bits_manual, in_block_manual, result_bits_manual);
    hash_comp_bits_manual.generate_assignments();
    hash_comp_bits_manual.generate_gates();
    BOOST_CHECK(expected_bits == result_bits_manual.get_digest());
    BOOST_CHECK(bp_bits_manual.is_satisfied());
}

/// hashing to bits
template<typename HashComponent>
void test_digest_variables_component_constructor(const std::vector<bool> &in_bits,
                                                 const std::vector<bool> &expected_bits) {
    using field_type = typename HashComponent::field_type;

    // input as container of block_variable
    blueprint<field_type> bp_bits, bp_bits_manual;
    std::size_t half_size = in_bits.size() / 2;
    components::digest_variable<field_type> in_block_left(bp_bits, half_size),
        in_block_right(bp_bits, in_bits.size() - half_size), in_block_manual_left(bp_bits_manual, half_size),
        in_block_manual_right(bp_bits_manual, in_bits.size() - half_size);
    in_block_left.generate_assignments(std::vector<bool>(std::cbegin(in_bits), std::cbegin(in_bits) + half_size));
    in_block_right.generate_assignments(std::vector<bool>(std::cbegin(in_bits) + half_size, std::cend(in_bits)));
    in_block_manual_left.generate_assignments(
        std::vector<bool>(std::cbegin(in_bits), std::cbegin(in_bits) + half_size));
    in_block_manual_right.generate_assignments(
        std::vector<bool>(std::cbegin(in_bits) + half_size, std::cend(in_bits)));

    // Auto allocation of the result
    HashComponent hash_comp_bits(bp_bits,
                                 std::vector {
                                     in_block_left,
                                     in_block_right,
                                 });
    hash_comp_bits.generate_assignments();
    hash_comp_bits.generate_gates();
    BOOST_CHECK(expected_bits == hash_comp_bits.result.get_digest());
    BOOST_CHECK(bp_bits.is_satisfied());

    // Manual allocation of the result
    typename HashComponent::result_type result_bits_manual(bp_bits_manual, field_type::value_bits);
    HashComponent hash_comp_bits_manual(bp_bits_manual,
                                        std::vector {
                                            in_block_manual_left,
                                            in_block_manual_right,
                                        },
                                        result_bits_manual);
    hash_comp_bits_manual.generate_assignments();
    hash_comp_bits_manual.generate_gates();
    BOOST_CHECK(expected_bits == result_bits_manual.get_digest());
    BOOST_CHECK(bp_bits_manual.is_satisfied());
}

// TODO: extend tests (check verification of wrong values)
template<typename Curve,
         typename HashToPointComponent = components::pedersen_to_point<Curve>,
         typename HashComponent = components::pedersen<Curve>>
void test_pedersen_default_params_component(
    const std::vector<bool> &in_bits,
    const typename HashToPointComponent::element_component::group_value_type &expected,
    const std::vector<bool> &expected_bits) {
    using field_type = typename HashToPointComponent::element_component::group_value_type::field_type;

    /// hashing to point
    test_blueprint_variable_vector_component_constructor<HashToPointComponent>(in_bits, expected);
    test_block_variable_component_constructor<HashToPointComponent>(in_bits, expected);
    test_block_variables_component_constructor<HashToPointComponent>(in_bits, expected);

    /// hashing to bits
    test_blueprint_variable_vector_component_constructor<HashComponent>(in_bits, expected_bits);
    test_digest_variable_component_constructor<HashComponent>(in_bits, expected_bits);
    test_digest_variables_component_constructor<HashComponent>(in_bits, expected_bits);
}

// TODO: extend tests, add checks of wrong values
BOOST_AUTO_TEST_SUITE(blueprint_pedersen_manual_test_suite)

// test data generated by https://github.com/zcash-hackworks/zcash-test-vectors
BOOST_AUTO_TEST_CASE(pedersen_jubjub_sha256_default_params_test) {
    using curve_type = curves::jubjub;
    using field_type = typename curve_type::base_field_type;
    using field_value_type = typename field_type::value_type;
    using integral_type = typename field_type::integral_type;

    std::vector<bool> bits_to_hash = {0, 0, 0, 1, 1, 1};
    auto expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("3669431847238482802904025485408296241776002230868041345055738963615665974946")),
            field_value_type(
                integral_type("27924821127213629235056488929093463445821551452792195607066067950495472725010")));
    std::vector<bool> expected_bits = {
        0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1,
        0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1,
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1,
        0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0,
        1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0,
        1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    test_pedersen_default_params_component<curve_type>(bits_to_hash, expected, expected_bits);

    // check work of internal padding
    bits_to_hash = {
        0, 0, 0, 1, 1,
    };
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("36263379031273262448220672699212876513597479199804632409115456999776988098218")),
            field_value_type(
                integral_type("31510484483269042758896724536623472863781228578271767290815193389100113348921")));
    expected_bits = {0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1,
                     0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1,
                     0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1,
                     1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                     1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1,
                     1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0,
                     0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0,
                     1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1};
    test_pedersen_default_params_component<curve_type>(bits_to_hash, expected, expected_bits);

    bits_to_hash = std::vector<bool> {0, 0, 1};
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("37613883148175089126541491300600635192159391899451195953263717773938227311808")),
            field_value_type(
                integral_type("52287259411977570791304693313354699485314647509298698724706688571292689216990")));
    expected_bits = {0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1,
                     1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0,
                     1, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1,
                     0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0,
                     1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1,
                     1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0,
                     1, 0, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0,
                     1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1};
    test_pedersen_default_params_component<curve_type>(bits_to_hash, expected, expected_bits);

    bits_to_hash = std::vector<bool> {0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1,
                                      0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1};
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("42176130776060636907007595971304534904965322197894055434176666599102076910022")),
            field_value_type(
                integral_type("41298132615767455442973386625334423316246314118050839847545855695501416927077")));
    expected_bits = {0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 1,
                     1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1,
                     0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
                     0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 0,
                     1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1,
                     0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1,
                     1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1,
                     0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1};
    test_pedersen_default_params_component<curve_type>(bits_to_hash, expected, expected_bits);

    bits_to_hash.resize(3 * 63 * 20);
    for (auto i = 0; i < bits_to_hash.size(); i++) {
        bits_to_hash[i] = std::vector<bool> {0, 0, 1}[i % 3];
    }
    expected =
        typename curve_type::template g1_type<curves::coordinates::affine, curves::forms::twisted_edwards>::value_type(
            field_value_type(
                integral_type("16831926627213193043296678235139527332739870606672735560230973395062624230202")),
            field_value_type(
                integral_type("29758113761493087483326459667018939508613372210858382541334106957041082715241")));
    expected_bits = {0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0,
                     0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1,
                     0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0,
                     0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1,
                     0, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1,
                     1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1,
                     1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1,
                     1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0};
    test_pedersen_default_params_component<curve_type>(bits_to_hash, expected, expected_bits);
}

BOOST_AUTO_TEST_SUITE_END()