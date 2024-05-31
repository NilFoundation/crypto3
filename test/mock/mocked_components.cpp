//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tablain <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_mock_tests

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>

#include <nil/blueprint/components/mock/mocked_components.hpp>

#include "../test_plonk_component.hpp"

using namespace nil;

#define ARITHMETIZATION_GEN \
    constexpr std::size_t WitnessColumns = 3; \
    constexpr std::size_t PublicInputColumns = 1; \
    constexpr std::size_t ConstantColumns = 0; \
    constexpr std::size_t SelectorColumns = 2; \
    zk::snark::plonk_table_description<BlueprintFieldType> desc( \
        WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns); \
    using ArithmetizationType = \
        crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType>; \
    using AssignmentType = blueprint::assignment<ArithmetizationType>; \
    using hash_type = crypto3::hashes::keccak_1600<256>; \
    constexpr std::size_t Lambda = 1;

#define TEST_SMALL_UNSIGNED_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType, unsigned Size> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a, \
            const typename BlueprintFieldType::value_type &b, \
            const typename BlueprintFieldType::value_type &expected_result) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType, Size>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a, b}; \
    \
        auto result_check = [&expected_result](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_result == var_value(assignment, real_res.a)); \
        }; \
    \
        component_type component_instance({0u, 1u, 2u}, {}, {}); \
        typename component_type::result_type(component_instance, 10); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

TEST_SMALL_UNSIGNED_GEN(test_small_unsigned_add, unsigned_addition_component_small)
TEST_SMALL_UNSIGNED_GEN(test_small_unsigned_sub, unsigned_subtraction_component_small)
TEST_SMALL_UNSIGNED_GEN(test_small_unsigned_mul, unsigned_multiplication_component_small)
TEST_SMALL_UNSIGNED_GEN(test_small_unsigned_div, unsigned_division_component_small)
TEST_SMALL_UNSIGNED_GEN(test_small_unsigned_rem, unsigned_remainder_component_small)

#define TEST_SMALL_SIGNED_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType, unsigned Size> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a_sign, \
            const typename BlueprintFieldType::value_type &a_mod, \
            const typename BlueprintFieldType::value_type &b_sign, \
            const typename BlueprintFieldType::value_type &b_mod, \
            const typename BlueprintFieldType::value_type &expected_result_sign, \
            const typename BlueprintFieldType::value_type &expected_result_mod) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType, Size>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
            var(0, 2, false, var::column_type::public_input), \
            var(0, 3, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a_sign, a_mod, b_sign, b_mod}; \
    \
        auto result_check = [&expected_result_sign, &expected_result_mod](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_result_sign == var_value(assignment, real_res.value[0])); \
            BOOST_ASSERT(expected_result_mod == var_value(assignment, real_res.value[1])); \
        }; \
    \
        component_type component_instance({0u, 1u, 2u}, {}, {}); \
        typename component_type::result_type(component_instance, 10u); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

TEST_SMALL_SIGNED_GEN(test_small_signed_add, signed_addition_component_small)
TEST_SMALL_SIGNED_GEN(test_small_signed_sub, signed_subtraction_component_small)
TEST_SMALL_SIGNED_GEN(test_small_signed_mul, signed_multiplication_component_small)
TEST_SMALL_SIGNED_GEN(test_small_signed_div, signed_division_component_small)
TEST_SMALL_SIGNED_GEN(test_small_signed_rem, signed_remainder_component_small)

static constexpr const int random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_mock_test_suite)

#define OP_ADDITION(a, b) (a + b)
#define OP_SUBTRACTION(a, b) (a - b)
#define OP_MULTIPLICATION(a, b) (a * b)
#define OP_DIVISION(a, b) (a / b)
#define OP_REMAINDER(a, b) (a % b)
#define OP_LESS(a, b) (a < b)
#define OP_LESS_EQ(a, b) (a <= b)
#define OP_GREATER(a, b) (a > b)
#define OP_GREATER_EQ(a, b) (a >= b)

#define OP_UNSIGNED_TEST_FUNC_GEN(NAME, TEST_NAME, OP, EX_1, EX_2, EX_3) \
    template<typename BlueprintFieldType, unsigned Size> \
    void NAME() { \
        using uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<Size>>; \
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<uint_type> \
            dist(0, boost::multiprecision::pow(uint_type(2), Size) - 1); \
        uint_type a = EX_1, b = EX_2; \
        TEST_NAME<BlueprintFieldType, Size>(a, b, EX_3); \
        for (std::size_t i = 0; i < random_tests_amount; i++) { \
            a = dist(seed_seq); \
            b = dist(seed_seq); \
            TEST_NAME<BlueprintFieldType, Size>(a, b, OP(a, b)); \
        } \
    }

#define OP_SIGNED_TEST_FUNC_GEN(NAME, TEST_NAME, OP) \
    template<typename BlueprintFieldType, unsigned Size> \
    void NAME() { \
        /* cpp_int_type is the one that exists in boost, it's not used by our code.*/ \
        using cpp_int_type = \
            boost::multiprecision::number< \
                boost::multiprecision::cpp_int_backend<Size, Size, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>; \
        using cpp_uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::cpp_int_backend<Size, Size, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>>; \
        using uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<Size>>; \
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<cpp_uint_type> \
            dist(0, boost::multiprecision::pow(cpp_uint_type(2), Size) - 1); \
        boost::random::uniform_int_distribution<char> sign_dist(0, 1); \
        for (std::size_t i = 0; i < 4 * random_tests_amount; i++) { \
            cpp_int_type a = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1); \
            cpp_int_type b = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1); \
            uint_type a_modular = typename uint_type::backend_type(cpp_uint_type(boost::multiprecision::abs(a)).backend()); \
            uint_type b_modular = typename uint_type::backend_type(cpp_uint_type(boost::multiprecision::abs(b)).backend()); \
            cpp_int_type result = OP(a, b); \
            uint_type result_modular = typename uint_type::backend_type(cpp_uint_type(boost::multiprecision::abs(result)).backend()); \
            TEST_NAME<BlueprintFieldType, Size>( \
                a >= 0 ? 0 : 1, a_modular, \
                b >= 0 ? 0 : 1, b_modular, \
                result.sign() >= 0 ? 0 : 1, result_modular); \
        } \
    }

OP_UNSIGNED_TEST_FUNC_GEN(
    test_small_unsigned_addition, test_small_unsigned_add, OP_ADDITION,
    1, boost::multiprecision::pow(uint_type(2), Size) - 1, 0)
OP_UNSIGNED_TEST_FUNC_GEN(
    test_small_unsigned_multiplication, test_small_unsigned_mul, OP_MULTIPLICATION,
    2, boost::multiprecision::pow(uint_type(2), Size - 1), 0)
OP_UNSIGNED_TEST_FUNC_GEN(
    test_small_unsigned_subtraction, test_small_unsigned_sub, OP_SUBTRACTION,
    0, boost::multiprecision::pow(uint_type(2), Size) - 1, 1);
OP_UNSIGNED_TEST_FUNC_GEN(
    test_small_unsigned_division, test_small_unsigned_div, OP_DIVISION, 1, 2, 0);
OP_UNSIGNED_TEST_FUNC_GEN(
    test_small_unsigned_remainder, test_small_unsigned_rem, OP_REMAINDER, 30, 3, 0);

OP_SIGNED_TEST_FUNC_GEN(test_small_signed_addition, test_small_signed_add, OP_ADDITION)
OP_SIGNED_TEST_FUNC_GEN(test_small_signed_subtraction, test_small_signed_sub, OP_SUBTRACTION)
OP_SIGNED_TEST_FUNC_GEN(test_small_signed_multiplication, test_small_signed_mul, OP_MULTIPLICATION)
OP_SIGNED_TEST_FUNC_GEN(test_small_signed_division, test_small_signed_div, OP_DIVISION)
OP_SIGNED_TEST_FUNC_GEN(test_small_signed_remainder, test_small_signed_rem, OP_REMAINDER)

// seprate infrastructure for abs
template<typename BlueprintFieldType, unsigned Size>
void test_small_signed_abs(
        const typename BlueprintFieldType::value_type &a_sign,
        const typename BlueprintFieldType::value_type &a_mod,
        const typename BlueprintFieldType::value_type &expected_sign,
        const typename BlueprintFieldType::value_type &expected_mod) {

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
    ARITHMETIZATION_GEN;
    using component_type =
        nil::blueprint::components::signed_abs_component_small<ArithmetizationType, BlueprintFieldType, Size>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
        var(0, 1, false, var::column_type::public_input),
    };

    std::vector<value_type> public_input = {a_sign, a_mod};

    auto result_check = [&expected_sign, &expected_mod](AssignmentType &assignment,
        typename component_type::result_type &real_res) {

        BOOST_ASSERT(expected_sign == var_value(assignment, real_res.value[0]));
        BOOST_ASSERT(expected_mod == var_value(assignment, real_res.value[1]));
    };

    component_type component_instance({0, 1, 2}, {}, {});
    typename component_type::result_type(component_instance, 10);

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::NONE);
}

template<typename BlueprintFieldType, unsigned Size>
void test_small_signed_absolute() {
    using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
        Size, Size, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>;
    using cpp_uint_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
        Size, Size, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>>;
    using uint_type = boost::multiprecision::number<boost::multiprecision::backends::cpp_int_modular_backend<Size>>;

    boost::random::mt19937 seed_seq;
    boost::random::uniform_int_distribution<cpp_uint_type>
        dist(0, boost::multiprecision::pow(cpp_uint_type(2), Size) - 1);
    boost::random::uniform_int_distribution<char> sign_dist(0, 1);
    for (std::size_t i = 0; i < 4 * random_tests_amount; i++) {
        cpp_int_type a = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1);
        uint_type a_modular = typename uint_type::backend_type(cpp_uint_type(boost::multiprecision::abs(a)).backend());
        test_small_signed_abs<BlueprintFieldType, Size>(
            a >= 0 ? 0 : 1, a_modular,
            0, a_modular);
    }
}

template<typename BlueprintFieldType>
void test_big_signed_abs(
        const typename BlueprintFieldType::value_type &a_sign,
        const typename BlueprintFieldType::value_type &a_first,
        const typename BlueprintFieldType::value_type &a_second,
        const typename BlueprintFieldType::value_type &expected_sign,
        const typename BlueprintFieldType::value_type &expected_first,
        const typename BlueprintFieldType::value_type &expected_second) {

    using value_type = typename BlueprintFieldType::value_type;
    using var = crypto3::zk::snark::plonk_variable<value_type>;
    ARITHMETIZATION_GEN;
    using component_type =
        nil::blueprint::components::signed_abs_component_big<ArithmetizationType, BlueprintFieldType>;

    typename component_type::input_type instance_input = {
        var(0, 0, false, var::column_type::public_input),
        var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input),
    };

    std::vector<value_type> public_input = {a_sign, a_first, a_second};

    auto result_check = [&expected_sign, &expected_first, &expected_second](AssignmentType &assignment,
        typename component_type::result_type &real_res) {

        BOOST_ASSERT(expected_sign == var_value(assignment, real_res.value[0]));
        BOOST_ASSERT(expected_first == var_value(assignment, real_res.value[1]));
        BOOST_ASSERT(expected_second == var_value(assignment, real_res.value[2]));
    };

    component_type component_instance({0, 1, 2}, {}, {});
    typename component_type::result_type(component_instance, 10);

    crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>(
        component_instance, desc, public_input, result_check, instance_input,
        nil::blueprint::connectedness_check_type::type::NONE);
}

template<typename BlueprintFieldType>
void test_big_signed_absolute() {
    using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            256u, 256u, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>;
    using cpp_uint_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<
            256u, 256u, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>>;
    using uint_type = boost::multiprecision::number<
            boost::multiprecision::backends::cpp_int_modular_backend<256u>>;
    
    boost::random::mt19937 seed_seq;
    boost::random::uniform_int_distribution<cpp_uint_type>
        dist(0, boost::multiprecision::pow(cpp_uint_type(2), 256) - 1);
    boost::random::uniform_int_distribution<char> sign_dist(0, 1);
    static const cpp_int_type top_mask = ((cpp_uint_type(1) << 128) - 1) << 128;
    static const cpp_int_type bottom_mask = (cpp_uint_type(1) << 128) - 1;
    for (std::size_t i = 0; i < 4 * random_tests_amount; i++) {
        cpp_int_type a = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1);
        cpp_int_type a_first = (a & top_mask) >> 128, 
                     a_second = a & bottom_mask;
        uint_type a_first_modular = typename uint_type::backend_type(cpp_uint_type(a_first).backend());
        uint_type a_second_modular = typename uint_type::backend_type(cpp_uint_type(a_second).backend());
        test_big_signed_abs<BlueprintFieldType>(
            a >= 0 ? 0 : 1, a_first_modular, a_second_modular,
            0, a_first_modular, a_second_modular);
    }
}

#define TEST_BIG_UNSIGNED_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a_first, \
            const typename BlueprintFieldType::value_type &a_second, \
            const typename BlueprintFieldType::value_type &b_first, \
            const typename BlueprintFieldType::value_type &b_second, \
            const typename BlueprintFieldType::value_type &expected_first, \
            const typename BlueprintFieldType::value_type &expected_second) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
            var(0, 2, false, var::column_type::public_input), \
            var(0, 3, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a_first, a_second, b_first, b_second}; \
    \
        auto result_check = [&expected_first, &expected_second](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_first == var_value(assignment, real_res.value[0])); \
            BOOST_ASSERT(expected_second == var_value(assignment, real_res.value[1])); \
        }; \
    \
        component_type component_instance({0, 1, 2}, {}, {}); \
        typename component_type::result_type(component_instance, 10); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

#define TEST_BIG_UNSIGNED_BOOL_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a_first, \
            const typename BlueprintFieldType::value_type &a_second, \
            const typename BlueprintFieldType::value_type &b_first, \
            const typename BlueprintFieldType::value_type &b_second, \
            const typename BlueprintFieldType::value_type &expected_result) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
            var(0, 2, false, var::column_type::public_input), \
            var(0, 3, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a_first, a_second, b_first, b_second}; \
    \
        auto result_check = [&expected_result](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_result == var_value(assignment, real_res.a)); \
        }; \
    \
        component_type component_instance({0, 1, 2}, {}, {}); \
        typename component_type::result_type(component_instance, 10); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

TEST_BIG_UNSIGNED_GEN(test_big_unsigned_add, unsigned_addition_component_big)
TEST_BIG_UNSIGNED_GEN(test_big_unsigned_sub, unsigned_subtraction_component_big)
TEST_BIG_UNSIGNED_GEN(test_big_unsigned_mul, unsigned_multiplication_component_big)
TEST_BIG_UNSIGNED_GEN(test_big_unsigned_div, unsigned_division_component_big)
TEST_BIG_UNSIGNED_GEN(test_big_unsigned_rem, unsigned_remainder_component_big)

TEST_BIG_UNSIGNED_BOOL_GEN(test_big_unsigned_less, unsinged_less_component_big)
TEST_BIG_UNSIGNED_BOOL_GEN(test_big_unsigned_less_eq, unsinged_less_equal_component_big)
TEST_BIG_UNSIGNED_BOOL_GEN(test_big_unsigned_greater, unsinged_greater_component_big)
TEST_BIG_UNSIGNED_BOOL_GEN(test_big_unsigned_greater_eq, unsinged_greater_equal_component_big)

#define TEST_BIG_SIGNED_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a_sign, \
            const typename BlueprintFieldType::value_type &a_first, \
            const typename BlueprintFieldType::value_type &a_second, \
            const typename BlueprintFieldType::value_type &b_sign, \
            const typename BlueprintFieldType::value_type &b_first, \
            const typename BlueprintFieldType::value_type &b_second, \
            const typename BlueprintFieldType::value_type &expected_sign, \
            const typename BlueprintFieldType::value_type &expected_first, \
            const typename BlueprintFieldType::value_type &expected_second) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
            var(0, 2, false, var::column_type::public_input), \
            var(0, 3, false, var::column_type::public_input), \
            var(0, 4, false, var::column_type::public_input), \
            var(0, 5, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a_sign, a_first, a_second, b_sign, b_first, b_second}; \
    \
        auto result_check = [&expected_sign, &expected_first, &expected_second](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_sign == var_value(assignment, real_res.value[0])); \
            BOOST_ASSERT(expected_first == var_value(assignment, real_res.value[1])); \
            BOOST_ASSERT(expected_second == var_value(assignment, real_res.value[2])); \
        }; \
    \
        component_type component_instance({0, 1, 2}, {}, {}); \
        typename component_type::result_type(component_instance, 10); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

TEST_BIG_SIGNED_GEN(test_big_signed_add, signed_addition_component_big)
TEST_BIG_SIGNED_GEN(test_big_signed_sub, signed_subtraction_component_big)
TEST_BIG_SIGNED_GEN(test_big_signed_mul, signed_multiplication_component_big)
TEST_BIG_SIGNED_GEN(test_big_signed_div, signed_division_component_big)
TEST_BIG_SIGNED_GEN(test_big_signed_rem, signed_remainder_component_big)

#define TEST_BIG_BOOL_SIGNED_GEN(FUNC_NAME, COMPONENT_NAME) \
    template<typename BlueprintFieldType> \
    void FUNC_NAME ( \
            const typename BlueprintFieldType::value_type &a_sign, \
            const typename BlueprintFieldType::value_type &a_first, \
            const typename BlueprintFieldType::value_type &a_second, \
            const typename BlueprintFieldType::value_type &b_sign, \
            const typename BlueprintFieldType::value_type &b_first, \
            const typename BlueprintFieldType::value_type &b_second, \
            const typename BlueprintFieldType::value_type &expected_result) { \
    \
        using value_type = typename BlueprintFieldType::value_type; \
        using var = crypto3::zk::snark::plonk_variable<value_type>; \
        ARITHMETIZATION_GEN; \
        using component_type = \
            nil::blueprint::components::COMPONENT_NAME<ArithmetizationType, BlueprintFieldType>; \
    \
        typename component_type::input_type instance_input = { \
            var(0, 0, false, var::column_type::public_input), \
            var(0, 1, false, var::column_type::public_input), \
            var(0, 2, false, var::column_type::public_input), \
            var(0, 3, false, var::column_type::public_input), \
            var(0, 4, false, var::column_type::public_input), \
            var(0, 5, false, var::column_type::public_input), \
        }; \
    \
        std::vector<value_type> public_input = {a_sign, a_first, a_second, b_sign, b_first, b_second}; \
    \
        auto result_check = [&expected_result](AssignmentType &assignment, \
            typename component_type::result_type &real_res) { \
    \
            BOOST_ASSERT(expected_result == var_value(assignment, real_res.a)); \
        }; \
    \
        component_type component_instance({0, 1, 2}, {}, {}); \
        typename component_type::result_type(component_instance, 10); \
    \
        crypto3::test_component<component_type, BlueprintFieldType, hash_type, Lambda>( \
            component_instance, desc, public_input, result_check, instance_input, \
            nil::blueprint::connectedness_check_type::type::NONE); \
    }

TEST_BIG_BOOL_SIGNED_GEN(test_big_signed_less, signed_less_component_big)
TEST_BIG_BOOL_SIGNED_GEN(test_big_signed_less_eq, signed_less_equal_component_big)
TEST_BIG_BOOL_SIGNED_GEN(test_big_signed_greater, signed_greater_component_big)
TEST_BIG_BOOL_SIGNED_GEN(test_big_signed_greater_eq, signed_greater_equal_component_big)

// TODO(martun): pallas is actually 255 bits, when moving 256-bit number into that field we are losing a bit. So far that does not result to an error, but better re-check.
#define OP_UNSIGNED_BIG_TEST_FUNC_GEN(NAME, TEST_NAME, OP) \
    template<typename BlueprintFieldType> \
    void NAME() { \
        using uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<256u>>; \
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<uint_type> \
            dist(0, boost::multiprecision::pow(uint_type(2), 256) - 1); \
        static const uint_type top_mask = ((uint_type(1) << 128) - 1) << 128; \
        static const uint_type bottom_mask = (uint_type(1) << 128) - 1; \
        for (std::size_t i = 0; i < random_tests_amount; i++) { \
            uint_type a = dist(seed_seq), \
                      b = dist(seed_seq); \
            uint_type expected_result = OP(a, b); \
            uint_type expected_first = (expected_result & top_mask) >> 128, \
                      expected_second = expected_result & bottom_mask; \
            TEST_NAME<BlueprintFieldType>((a & top_mask) >> 128, a & bottom_mask, \
                                          (b & top_mask) >> 128, b & bottom_mask, \
                                          expected_first, expected_second); \
        } \
    }

#define OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN(NAME, TEST_NAME, OP) \
    template<typename BlueprintFieldType> \
    void NAME() { \
        using uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<256u>>; \
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<uint_type> \
            dist(0, boost::multiprecision::pow(uint_type(2), 256) - 1); \
        static const uint_type top_mask = ((uint_type(1) << 128) - 1) << 128; \
        static const uint_type bottom_mask = (uint_type(1) << 128) - 1; \
        for (std::size_t i = 0; i < random_tests_amount; i++) { \
            uint_type a = dist(seed_seq), \
                      b = dist(seed_seq); \
            bool expected_result = OP(a, b); \
            TEST_NAME<BlueprintFieldType>((a & top_mask) >> 128, a & bottom_mask, \
                                          (b & top_mask) >> 128, b & bottom_mask, \
                                          expected_result); \
        } \
    }

OP_UNSIGNED_BIG_TEST_FUNC_GEN(test_big_unsigned_addition, test_big_unsigned_add, OP_ADDITION)
OP_UNSIGNED_BIG_TEST_FUNC_GEN(test_big_unsigned_subtraction, test_big_unsigned_sub, OP_SUBTRACTION)
OP_UNSIGNED_BIG_TEST_FUNC_GEN(test_big_unsigned_multiplication, test_big_unsigned_mul, OP_MULTIPLICATION)
OP_UNSIGNED_BIG_TEST_FUNC_GEN(test_big_unsigned_division, test_big_unsigned_div, OP_DIVISION)
OP_UNSIGNED_BIG_TEST_FUNC_GEN(test_big_unsigned_remainder, test_big_unsigned_rem, OP_REMAINDER)

OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_unsigned_less_than, test_big_unsigned_less, OP_LESS)
OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_unsigned_less_than_eq, test_big_unsigned_less_eq, OP_LESS_EQ)
OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_unsigned_greater_than, test_big_unsigned_greater, OP_GREATER)
OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_unsigned_greater_than_eq, test_big_unsigned_greater_eq, OP_GREATER_EQ)


#define OP_SIGNED_BIG_TEST_FUNC_GEN(NAME, TEST_NAME, OP) \
    template<typename BlueprintFieldType> \
    void NAME() { \
        using cpp_int_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend< \
            256u, 256u, boost::multiprecision::signed_magnitude, boost::multiprecision::unchecked>>; \
        using cpp_uint_type = boost::multiprecision::number<boost::multiprecision::cpp_int_backend< \
            256u, 256u, boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked>>; \
        using uint_type = boost::multiprecision::number< \
            boost::multiprecision::backends::cpp_int_modular_backend<256u>>; \
\
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<cpp_uint_type> \
            dist(0, boost::multiprecision::pow(cpp_uint_type(2), 256) - 1); \
        boost::random::uniform_int_distribution<char> sign_dist(0, 1); \
        static const cpp_int_type top_mask = ((cpp_int_type(1) << 128) - 1) << 128; \
        static const cpp_int_type bottom_mask = (cpp_int_type(1) << 128) - 1; \
        for (std::size_t i = 0; i < 4 * random_tests_amount; i++) { \
            cpp_int_type a = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1), \
                     b = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1); \
            cpp_int_type expected_result = OP(a, b); \
            cpp_int_type expected_first = (expected_result & top_mask) >> 128, \
                     expected_second = expected_result & bottom_mask; \
            cpp_int_type a_top = (a & top_mask) >> 128; \
            cpp_int_type a_bottom = a & bottom_mask; \
            cpp_int_type b_top = (b & top_mask) >> 128; \
            cpp_int_type b_bottom = b & bottom_mask; \
\
            uint_type expected_first_modular = typename uint_type::backend_type(cpp_uint_type(expected_first).backend()); \
            uint_type expected_second_modular = typename uint_type::backend_type(cpp_uint_type(expected_second).backend()); \
            uint_type a_top_modular = typename uint_type::backend_type(cpp_uint_type(a_top).backend()); \
            uint_type a_bottom_modular = typename uint_type::backend_type(cpp_uint_type(a_bottom).backend()); \
            uint_type b_top_modular = typename uint_type::backend_type(cpp_uint_type(b_top).backend()); \
            uint_type b_bottom_modular = typename uint_type::backend_type(cpp_uint_type(b_bottom).backend()); \
\
            TEST_NAME<BlueprintFieldType>(a.sign() >= 0 ? 0 : 1, a_top_modular, a_bottom_modular, \
                                          b.sign() >= 0 ? 0 : 1, b_top_modular, b_bottom_modular, \
                                          expected_result.sign() >= 0 ? 0 : 1, expected_first_modular, expected_second_modular); \
        } \
    }

#define OP_SIGNED_BIG_BOOL_TEST_FUNC_GEN(NAME, TEST_NAME, OP) \
    template<typename BlueprintFieldType> \
    void NAME() { \
        using int_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<256u>>; \
        using uint_type = \
            boost::multiprecision::number< \
                boost::multiprecision::backends::cpp_int_modular_backend<256u>>; \
        boost::random::mt19937 seed_seq; \
        boost::random::uniform_int_distribution<uint_type> \
            dist(0, boost::multiprecision::pow(uint_type(2), 256) - 1); \
        boost::random::uniform_int_distribution<char> sign_dist(0, 1); \
        static const int_type top_mask = ((int_type(1) << 128) - 1) << 128; \
        static const int_type bottom_mask = (int_type(1) << 128) - 1; \
        for (std::size_t i = 0; i < 4 * random_tests_amount; i++) { \
            int_type a = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1), \
                     b = dist(seed_seq) * (sign_dist(seed_seq) ? 1 : -1); \
            TEST_NAME<BlueprintFieldType>(a.sign() >= 0 ? 0 : 1, (a & top_mask) >> 128, a & bottom_mask, \
                                          b.sign() >= 0 ? 0 : 1, (b & top_mask) >> 128, b & bottom_mask, \
                                          OP(a, b)); \
        } \
    }

OP_SIGNED_BIG_TEST_FUNC_GEN(test_big_signed_addition, test_big_signed_add, OP_ADDITION)
OP_SIGNED_BIG_TEST_FUNC_GEN(test_big_signed_subtraction, test_big_signed_sub, OP_SUBTRACTION)
OP_SIGNED_BIG_TEST_FUNC_GEN(test_big_signed_multiplication, test_big_signed_mul, OP_MULTIPLICATION)
OP_SIGNED_BIG_TEST_FUNC_GEN(test_big_signed_division, test_big_signed_div, OP_DIVISION)
OP_SIGNED_BIG_TEST_FUNC_GEN(test_big_signed_remainder, test_big_signed_rem, OP_REMAINDER)

OP_SIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_signed_less_than, test_big_signed_less, OP_LESS)
OP_SIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_signed_less_than_eq, test_big_signed_less_eq, OP_LESS_EQ)
OP_SIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_signed_greater_than, test_big_signed_greater, OP_GREATER)
OP_SIGNED_BIG_BOOL_TEST_FUNC_GEN(test_big_signed_greater_than_eq, test_big_signed_greater_eq, OP_GREATER_EQ)

#define OP_TEST(TEST_NAME) \
    BOOST_AUTO_TEST_CASE(blueprint_ ## TEST_NAME ## _mock) { \
        using field_type = crypto3::algebra::curves::pallas::base_field_type; \
        TEST_NAME<field_type, 8u>(); \
        TEST_NAME<field_type, 16u>(); \
        TEST_NAME<field_type, 32u>(); \
        TEST_NAME<field_type, 64u>(); \
        TEST_NAME<field_type, 128u>(); \
    }

#define OP_BIG_TEST(TEST_NAME) \
    BOOST_AUTO_TEST_CASE(blueprint_ ## TEST_NAME ## _mock) { \
        using field_type = crypto3::algebra::curves::pallas::base_field_type; \
        TEST_NAME<field_type>(); \
    }

OP_TEST(test_small_unsigned_addition);
OP_TEST(test_small_unsigned_multiplication);
OP_TEST(test_small_unsigned_subtraction);
OP_TEST(test_small_unsigned_division);
OP_TEST(test_small_unsigned_remainder);

OP_TEST(test_small_signed_addition);
OP_TEST(test_small_signed_subtraction);
OP_TEST(test_small_signed_multiplication);
OP_TEST(test_small_signed_division);
OP_TEST(test_small_signed_remainder);

OP_TEST(test_small_signed_absolute);

OP_BIG_TEST(test_big_unsigned_addition);
OP_BIG_TEST(test_big_unsigned_subtraction);
OP_BIG_TEST(test_big_unsigned_multiplication);
OP_BIG_TEST(test_big_unsigned_division);
OP_BIG_TEST(test_big_unsigned_remainder);

OP_BIG_TEST(test_big_unsigned_less_than);
OP_BIG_TEST(test_big_unsigned_less_than_eq);
OP_BIG_TEST(test_big_unsigned_greater_than);
OP_BIG_TEST(test_big_unsigned_greater_than_eq);

OP_BIG_TEST(test_big_signed_addition);
OP_BIG_TEST(test_big_signed_subtraction);
OP_BIG_TEST(test_big_signed_multiplication);
OP_BIG_TEST(test_big_signed_division);
OP_BIG_TEST(test_big_signed_remainder);

OP_BIG_TEST(test_big_signed_less_than);
OP_BIG_TEST(test_big_signed_less_than_eq);
OP_BIG_TEST(test_big_signed_greater_than);
OP_BIG_TEST(test_big_signed_greater_than_eq);

OP_BIG_TEST(test_big_signed_absolute);

#undef ARITHMETIZATION_GEN
#undef OP_TEST
#undef OP_BIG_TEST

#undef OP_ADDITION
#undef OP_SUBTRACTION
#undef OP_MULTIPLICATION
#undef OP_DIVISION
#undef OP_REMAINDER
#undef OP_LESS
#undef OP_LESS_EQ
#undef OP_GREATER
#undef OP_GREATER_EQ

#undef OP_UNSIGNED_TEST_FUNC_GEN
#undef OP_SIGNED_TEST_FUNC_GEN
#undef OP_UNSIGNED_BIG_TEST_FUNC_GEN
#undef OP_UNSIGNED_BIG_BOOL_TEST_FUNC_GEN
#undef OP_SIGNED_BIG_TEST_FUNC_GEN

BOOST_AUTO_TEST_SUITE_END()
