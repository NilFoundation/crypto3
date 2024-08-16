//---------------------------------------------------------------------------//
// Copyright (c) 2023 Dmitrii Tabalin <d.tabalin@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_manifest_test

#include <boost/test/unit_test.hpp>
#include <boost/integer/extended_euclidean.hpp>

#include <memory>
#include <map>
#include <functional>

#include <nil/blueprint/manifest.hpp>

using namespace nil::blueprint;

BOOST_AUTO_TEST_SUITE(blueprint_manifest_test_suite)

void test_manifest_range_intersect(std::int32_t start_1, std::int32_t end_1, std::uint32_t step_1,
                                   std::int32_t start_2, std::int32_t end_2, std::uint32_t step_2) {
    std::shared_ptr<manifest_param> param_1 = std::make_shared<manifest_range_param>(start_1, end_1, step_1);
    std::shared_ptr<manifest_param> param_2 = std::make_shared<manifest_range_param>(start_2, end_2, step_2);
    std::shared_ptr<manifest_param> result = param_1->intersect(param_2);

    std::int32_t new_start, new_end, new_step;
    if (step_1 == step_2) {
        new_start = std::max(start_1, start_2);
        new_end = std::min(end_1, end_2);
        new_step = step_1;
        if (new_start >= new_end) {
            BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::UNSAT);
        } else if (new_start == new_end - 1) {
            BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::SINGLE_VALUE);
            manifest_single_value_param* res = dynamic_cast<manifest_single_value_param*>(result.get());
            BOOST_ASSERT(res->value == std::size_t(new_start));
        } else {
            BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::RANGE);
            manifest_range_param* res = dynamic_cast<manifest_range_param*>(result.get());
            BOOST_ASSERT(res->start == new_start);
            BOOST_ASSERT(res->finish == new_end);
            BOOST_ASSERT(res->step == std::size_t(new_step));
        }
    } else {
        auto [gcd, m, n] = boost::integer::extended_euclidean<std::int32_t>(step_1, step_2);
        if (start_1 % gcd != start_2 % gcd) {
            BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::UNSAT);
        } else {
            new_step = step_1 * (step_2 / gcd);
            std::uint32_t result_modulo_new_step =
                (new_step + ((start_1 * int(step_2) * n + start_2 * int(step_1) * m) / gcd) % new_step) % new_step;
            new_start = std::max(start_1, start_2);
            new_start = new_start + (new_step + int(result_modulo_new_step - new_start) % new_step) % new_step;
            new_end = std::min(end_1, end_2);
            if (new_start >= new_end) {
                BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::UNSAT);
            } else if (new_start == new_end - 1) {
                BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::SINGLE_VALUE);
                manifest_single_value_param* res = dynamic_cast<manifest_single_value_param*>(result.get());
                BOOST_ASSERT(res->value == std::size_t(new_start));
            } else {
                BOOST_ASSERT(get_manifest_param_type(result) == manifest_param::type::RANGE);
                manifest_range_param* res = dynamic_cast<manifest_range_param*>(result.get());
                BOOST_ASSERT(res->start == new_start);
                BOOST_ASSERT(res->finish == new_end);
                BOOST_ASSERT(res->step == std::size_t(new_step));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(test_manifest_range_intersection) {
    test_manifest_range_intersect(1, 10, 2, 5, 120, 2);
    test_manifest_range_intersect(1, 10, 2, 5, 15, 3);
    test_manifest_range_intersect(20, 100, 14, 50, 150, 6);
    test_manifest_range_intersect(21, 100, 14, 49, 150, 7);
    test_manifest_range_intersect(123, 1000, 30, 49, 150, 17);
    test_manifest_range_intersect(21, 91, 14, 49, 150, 7);
    test_manifest_range_intersect(0, 10, 1, 3, 12, 3);
    test_manifest_range_intersect(2, 3, 1, 2, 3, 1);
}

void test_operator(std::shared_ptr<manifest_param> param_1,
                   std::shared_ptr<manifest_param> param_2,
                   std::shared_ptr<manifest_param> expected_result,
                   const std::function<std::shared_ptr<manifest_param>(std::shared_ptr<manifest_param>,
                                                                       std::shared_ptr<manifest_param>)> &oper) {
    std::shared_ptr<manifest_param> result = oper(param_1, param_2);
    std::shared_ptr<manifest_param> result_2 = oper(param_2, param_1);
    BOOST_ASSERT(get_manifest_param_type(result) == get_manifest_param_type(expected_result));
    BOOST_ASSERT(get_manifest_param_type(result_2) == get_manifest_param_type(expected_result));
    auto type = get_manifest_param_type(expected_result);
    if (type == manifest_param::type::UNSAT) {
        return;
    } else if (type == manifest_param::type::SINGLE_VALUE) {
        auto value_1 = dynamic_cast<manifest_single_value_param*>(result.get())->value;
        auto value_2 = dynamic_cast<manifest_single_value_param*>(expected_result.get())->value;
        BOOST_ASSERT(value_1 == value_2);
        auto value_3 = dynamic_cast<manifest_single_value_param*>(result_2.get())->value;
        BOOST_ASSERT(value_3 == value_2);
    } else if (type == manifest_param::type::SET) {
        auto set_1 = dynamic_cast<manifest_set_param*>(result.get())->set;
        auto set_2 = dynamic_cast<manifest_set_param*>(expected_result.get())->set;
        BOOST_ASSERT(set_1 == set_2);
        auto set_3 = dynamic_cast<manifest_set_param*>(result_2.get())->set;
        BOOST_ASSERT(set_3 == set_2);
    } else if (type == manifest_param::type::RANGE) {
        auto range_1 = dynamic_cast<manifest_range_param*>(result.get());
        auto range_2 = dynamic_cast<manifest_range_param*>(expected_result.get());
        BOOST_ASSERT(*range_1 == *range_2);
        auto range_3 = dynamic_cast<manifest_range_param*>(result_2.get());
        BOOST_ASSERT(*range_3 == *range_2);
    } else {
        BOOST_ASSERT(false);
    }
}

BOOST_AUTO_TEST_CASE(test_manifest_param_intersection) {
    auto intersection_tester = [](std::shared_ptr<manifest_param> param_1,
                                        std::shared_ptr<manifest_param> param_2) {
        return param_1->intersect(param_2);
    };
    std::shared_ptr<manifest_param> param_1 = std::make_shared<manifest_single_value_param>(5);
    std::shared_ptr<manifest_param> param_2 = std::make_shared<manifest_single_value_param>(5);
    std::shared_ptr<manifest_param> result_1 = std::make_shared<manifest_single_value_param>(5);
    test_operator(param_1, param_2, result_1, intersection_tester);

    std::shared_ptr<manifest_param> param_3 = std::make_shared<manifest_single_value_param>(6);
    std::shared_ptr<manifest_param> result_2 = std::make_shared<manifest_unsat_param>();
    test_operator(param_1, param_3, result_2, intersection_tester);

    std::shared_ptr<manifest_param> param_4 = std::make_shared<manifest_range_param>(0, 10, 1);
    std::shared_ptr<manifest_param> result_3 = std::make_shared<manifest_single_value_param>(5);
    test_operator(param_1, param_4, result_3, intersection_tester);

    std::shared_ptr<manifest_param> param_5 = std::make_shared<manifest_set_param>(
        std::set<std::uint32_t>{0, 2, 5, 120});
    std::shared_ptr<manifest_param> result_4 = std::make_shared<manifest_single_value_param>(5);
    test_operator(param_1, param_5, result_4, intersection_tester);

    std::shared_ptr<manifest_param> result_5 = std::make_shared<manifest_set_param>(
        std::set<std::uint32_t>{0, 2, 5}
    );
    test_operator(param_5, param_4, result_5, intersection_tester);
}

BOOST_AUTO_TEST_CASE(test_manifest_param_merge_with) {
    auto merge_tester = [](std::shared_ptr<manifest_param> param_1,
                                     std::shared_ptr<manifest_param> param_2) {
        return param_1->merge_with(param_2);
    };

    std::shared_ptr<manifest_param> param_1 = std::make_shared<manifest_single_value_param>(5);
    std::shared_ptr<manifest_param> param_2 = std::make_shared<manifest_single_value_param>(11);
    std::shared_ptr<manifest_param> result_1 = std::make_shared<manifest_single_value_param>(11);
    test_operator(param_1, param_2, result_1, merge_tester);

    std::shared_ptr<manifest_param> param_3 = std::make_shared<manifest_range_param>(0, 10, 1);
    std::shared_ptr<manifest_param> result_2 = std::make_shared<manifest_range_param>(5, 10, 1);
    test_operator(param_3, param_1, result_2, merge_tester);
    test_operator(param_2, param_3, param_2, merge_tester);
    test_operator(result_2, param_3, result_2, merge_tester);

    std::shared_ptr<manifest_param> param_4 = std::make_shared<manifest_range_param>(10, 20, 2);
    test_operator(param_4, param_3, param_4, merge_tester);
    std::shared_ptr<manifest_param> param_5 = std::make_shared<manifest_set_param>(
        std::set<std::uint32_t>{0, 1, 2, 3, 4, 5, 91, 11});
    std::shared_ptr<manifest_param> result_3 = std::make_shared<manifest_set_param>(
        std::set<std::uint32_t>{11, 12, 14, 16, 18, 91});
    test_operator(param_5, param_4, result_3, merge_tester);

    std::shared_ptr<manifest_param> param_6 = std::make_shared<manifest_range_param>(9, 28, 3);
    std::shared_ptr<manifest_param> result_4 = std::make_shared<manifest_set_param>(std::set<std::uint32_t>{
        10, 12, 14, 16, 18, 15, 18, 21, 24, 27
    });
    test_operator(param_6, param_4, result_4, merge_tester);
}

BOOST_AUTO_TEST_CASE(test_manifest_iteration) {
    manifest_single_value_param param(5);
    std::size_t i = 0;
    for (auto val : param) {
        BOOST_ASSERT(val == 5);
        ++i;
    }
    BOOST_ASSERT(i == 1);

    using manifest_set_param = manifest_set_param;
    std::set<std::uint32_t> expected_set = {0, 1, 2, 3, 4, 5, 91, 11};
    manifest_set_param param_set(expected_set);

    std::size_t j = 0;
    for (auto val : param_set) {
        BOOST_ASSERT(expected_set.find(val) != expected_set.end());
        ++j;
    }
    BOOST_ASSERT(j == expected_set.size());

    using manifest_range_param = manifest_range_param;
    manifest_range_param param_range(1, 16, 2);
    std::set<std::int32_t> expected_range = {1, 3, 5, 7, 9, 11, 13, 15};
    std::size_t k = 0;
    for (auto val : param_range) {
        BOOST_ASSERT(expected_range.find(val) != expected_range.end());
        ++k;
    }
    BOOST_ASSERT(k == expected_range.size());
}

template<typename TestType1, typename TestType2 = TestType1>
void test_table_operation(const std::map<std::pair<TestType1, TestType2>, TestType1> &test_table,
                          const std::function<TestType1(const TestType1&, const TestType2&)> &operation) {
    for (auto test_case : test_table) {
        auto [type_1, type_2] = test_case.first;
        auto expected_result = test_case.second;
        auto result = operation(type_1, type_2);
        BOOST_ASSERT(result == expected_result);
        if constexpr (std::is_same_v<TestType1, TestType2>) {
            auto second_result = operation(type_2, type_1);
            BOOST_ASSERT(second_result == expected_result);
        }
    }
}

BOOST_AUTO_TEST_CASE(test_manifest_constant_type_intersection) {
    compiler_manifest
        has_constant(0, true),
        has_no_constant(0, false);
    std::map<std::pair<manifest_constant_type, compiler_manifest>, manifest_constant_type>
            intersection_test_table = {
        {{manifest_constant_type::type::UNSAT, has_constant}, manifest_constant_type::type::UNSAT},
        {{manifest_constant_type::type::UNSAT, has_no_constant}, manifest_constant_type::type::UNSAT},
        {{manifest_constant_type::type::NONE, has_constant}, manifest_constant_type::type::NONE},
        {{manifest_constant_type::type::NONE, has_no_constant}, manifest_constant_type::type::NONE},
        {{manifest_constant_type::type::REQUIRED, has_constant}, manifest_constant_type::type::REQUIRED},
        {{manifest_constant_type::type::REQUIRED, has_no_constant}, manifest_constant_type::type::UNSAT},
    };
    std::function<manifest_constant_type(const manifest_constant_type&, const compiler_manifest&)> test_intersect
        = [](const manifest_constant_type &type_1, const compiler_manifest &type_2) {
            return type_1.intersect(type_2);
    };

    test_table_operation(intersection_test_table, test_intersect);
}

BOOST_AUTO_TEST_CASE(test_manifest_constant_type_merge_with) {
    std::map<std::pair<manifest_constant_type, manifest_constant_type>, manifest_constant_type>
            merge_with_test_table = {
        {{manifest_constant_type::type::UNSAT, manifest_constant_type::type::UNSAT}, manifest_constant_type::type::UNSAT},
        {{manifest_constant_type::type::UNSAT, manifest_constant_type::type::NONE}, manifest_constant_type::type::UNSAT},
        {{manifest_constant_type::type::UNSAT, manifest_constant_type::type::REQUIRED}, manifest_constant_type::type::UNSAT},
        {{manifest_constant_type::type::NONE, manifest_constant_type::type::NONE}, manifest_constant_type::type::NONE},
        {{manifest_constant_type::type::NONE, manifest_constant_type::type::REQUIRED}, manifest_constant_type::type::REQUIRED},
        {{manifest_constant_type::type::REQUIRED, manifest_constant_type::type::REQUIRED}, manifest_constant_type::type::REQUIRED},
    };
    std::function<manifest_constant_type(const manifest_constant_type&, const manifest_constant_type&)> test_merge_with
        = [](const manifest_constant_type &type_1, const manifest_constant_type &type_2) {
            return type_1.merge_with(type_2);
    };

    test_table_operation(merge_with_test_table, test_merge_with);
}

bool check_param_equality(const std::shared_ptr<manifest_param>& param_1,
                          const std::shared_ptr<manifest_param>& param_2) {
    if (get_manifest_param_type(param_1) != get_manifest_param_type(param_2)) {
        return false;
    }
    manifest_param::type type = get_manifest_param_type(param_1);
    switch (type) {
        case manifest_param::type::UNSAT:
            return dynamic_cast<manifest_unsat_param*>(param_1.get())->operator==(
                   *dynamic_cast<manifest_unsat_param*>(param_2.get()));
        case manifest_param::type::SINGLE_VALUE:
            return dynamic_cast<manifest_single_value_param*>(param_1.get())->operator==(
                   *dynamic_cast<manifest_single_value_param*>(param_2.get()));
        case manifest_param::type::RANGE:
            return dynamic_cast<manifest_range_param*>(param_1.get())->operator==(
                   *dynamic_cast<manifest_range_param*>(param_2.get()));
        case manifest_param::type::SET:
            return dynamic_cast<manifest_set_param*>(param_1.get())->operator==(
                   *dynamic_cast<manifest_set_param*>(param_2.get()));
        default:
            return false;
    }
}

bool check_manifest_equality(const plonk_component_manifest& manifest_1,
                             const plonk_component_manifest& manifest_2) {
    if (!check_param_equality(manifest_1.witness_amount, manifest_2.witness_amount)) {
        return false;
    }
    if (manifest_1.constant_required != manifest_2.constant_required) {
        return false;
    }
    return true;
}

BOOST_AUTO_TEST_CASE(test_manifest_intersect) {
    compiler_manifest comp_manifest_1(9, false);
    plonk_component_manifest manifest_1(
        std::make_shared<manifest_range_param>(3, 12, 3),
        manifest_constant_type::type::NONE);
    plonk_component_manifest manifest_res_1 = comp_manifest_1.intersect(manifest_1);
    plonk_component_manifest expected_res_1 = plonk_component_manifest(
        std::make_shared<manifest_range_param>(3, 10, 3),
        manifest_constant_type::type::NONE);
    BOOST_ASSERT(check_manifest_equality(manifest_res_1, expected_res_1));

    plonk_component_manifest manifest_2(
        std::make_shared<manifest_range_param>(3, 12, 3),
        manifest_constant_type::type::NONE);
    plonk_component_manifest manifest_res_2 = comp_manifest_1.intersect(manifest_2);
    plonk_component_manifest expected_res_2 = plonk_component_manifest(
        std::make_shared<manifest_range_param>(3, 10, 3),
        manifest_constant_type::type::NONE);
    BOOST_ASSERT(check_manifest_equality(manifest_res_2, expected_res_2));

    plonk_component_manifest manifest_3(
        std::make_shared<manifest_single_value_param>(5),
        manifest_constant_type::type::REQUIRED);
    plonk_component_manifest manifest_res_3 = comp_manifest_1.intersect(manifest_3);
    plonk_component_manifest expected_res_3 = plonk_component_manifest(
        std::make_shared<manifest_single_value_param>(5),
        manifest_constant_type::type::UNSAT);
    BOOST_ASSERT(check_manifest_equality(manifest_res_3, expected_res_3));

    compiler_manifest comp_manifest_2(20, true);
    plonk_component_manifest manifest_4(
        std::make_shared<manifest_set_param>(std::set<std::uint32_t>{1, 2, 3, 11, 21, 22}),
        manifest_constant_type::type::REQUIRED);
    plonk_component_manifest manifest_res_4 = comp_manifest_2.intersect(manifest_4);
    plonk_component_manifest expected_res_4 = plonk_component_manifest(
        std::make_shared<manifest_set_param>(std::set<std::uint32_t>{1, 2, 3, 11}),
        manifest_constant_type::type::REQUIRED);
    BOOST_ASSERT(check_manifest_equality(manifest_res_4, expected_res_4));
}

BOOST_AUTO_TEST_SUITE_END()