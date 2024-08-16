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

#define BOOST_TEST_MODULE blueprint_huang_lu_test

#include <boost/test/unit_test.hpp>

#include <nil/blueprint/detail/huang_lu.hpp>

#include <unordered_map>
#include <list>
#include <algorithm>
#include <cstdlib>

using namespace nil::blueprint::components::detail;

BOOST_AUTO_TEST_SUITE(blueprint_huang_lu_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_huang_lu_basic) {
    std::list<std::pair<std::size_t, std::size_t>> sizes = {
        {0, 1}, {1, 2}, {2, 3}, {3, 4}, {4, 5}
    };
    std::size_t agent_amount = 2;

    std::unordered_map<std::size_t, std::size_t> assignment = huang_lu(sizes, agent_amount);

    BOOST_CHECK_EQUAL(assignment[0], 1);
    BOOST_CHECK_EQUAL(assignment[1], 1);
    BOOST_CHECK_EQUAL(assignment[2], 0);
    BOOST_CHECK_EQUAL(assignment[3], 1);
    BOOST_CHECK_EQUAL(assignment[4], 0);

    agent_amount = 3;
    assignment = huang_lu(sizes, agent_amount);
    BOOST_CHECK_EQUAL(assignment[0], 1);
    BOOST_CHECK_EQUAL(assignment[1], 2);
    BOOST_CHECK_EQUAL(assignment[2], 2);
    BOOST_CHECK_EQUAL(assignment[3], 1);
    BOOST_CHECK_EQUAL(assignment[4], 0);

    // sanity
    agent_amount = 1;
    assignment = huang_lu(sizes, agent_amount);
    BOOST_CHECK_EQUAL(assignment[0], 0);
    BOOST_CHECK_EQUAL(assignment[1], 0);
    BOOST_CHECK_EQUAL(assignment[2], 0);
    BOOST_CHECK_EQUAL(assignment[3], 0);
    BOOST_CHECK_EQUAL(assignment[4], 0);
}

std::pair<std::size_t, bool> exhaustive_value_search(std::vector<std::size_t> &sizes,
                                                     std::vector<std::size_t> &tasks,
                                                     std::size_t curr_task,
                                                     std::size_t branching_threshold,
                                                     bool result_found = false) {
    if (curr_task < tasks.size()) {
        for (std::size_t j = 0; j < sizes.size(); j++) {
            if (sizes[j] + tasks[curr_task] <= branching_threshold) {
                sizes[j] += tasks[curr_task];
                auto [value, act_result_found] =
                    exhaustive_value_search(sizes, tasks, curr_task + 1, branching_threshold, result_found);
                if (value <= branching_threshold && act_result_found) {
                    branching_threshold = value;
                    result_found = true;
                }
                sizes[j] -= tasks[curr_task];
            }
        }
    } else if (curr_task == tasks.size()) {
        result_found = true;
        std::size_t new_branching_threshold = 0;
        for (std::size_t i = 0; i < sizes.size(); i++) {
            new_branching_threshold = std::max(new_branching_threshold, sizes[i]);
        }
        branching_threshold = new_branching_threshold;
    }
    return std::make_pair(branching_threshold, result_found);
}

void test_against_exhaustive_search(std::list<std::pair<std::size_t, std::size_t>> &sizes,
                                    std::size_t agent_amount) {
    std::unordered_map<std::size_t, std::size_t> assignment = huang_lu(sizes, agent_amount);
    // Sanity check: all tasks are assigned
    for (std::size_t i = 0; i < sizes.size(); i++) {
        BOOST_ASSERT(assignment.find(i) != assignment.end());
    }
    std::vector<std::size_t> tasks(sizes.size(), 0);
    for (auto [key, size] : sizes) {
        tasks[key] = size;
    }
    std::vector<std::size_t> sizes_for_exhaustive_search(agent_amount, 0);
    for (auto [task, agent] : assignment) {
        sizes_for_exhaustive_search[agent] += tasks[task];
    }
    std::size_t value = 0;
    for (std::size_t i = 0; i < agent_amount; i++) {
        value = std::max(value, sizes_for_exhaustive_search[i]);
        sizes_for_exhaustive_search[i] = 0;
    }
    auto [true_value, result_found] = exhaustive_value_search(
        sizes_for_exhaustive_search,
        tasks,
        0,
        value);
    BOOST_ASSERT(result_found);
    BOOST_ASSERT(9 * value <= true_value * 11);
}

// Reduce this if you want to make the instances bigger
// The testing data is basically calculated by brute force
// So on bigger instances exponetial growth will make the tests real long
// Another approach is to precompute test result values
// Might be worth it?
constexpr static const std::size_t random_tests_amount = 40;

BOOST_AUTO_TEST_CASE(blueprint_huang_lu_bruteforce_small_instance) {
    std::srand(1337);
    for (std::size_t i = 0; i < random_tests_amount; i++) {
        // Generate random amount of agents, tasks and their sizes
        std::size_t agent_amount = std::rand() % 6 + 1;
        std::size_t tasks_amount = std::rand() % 17 + 1;
        std::list<std::pair<std::size_t, std::size_t>> sizes;
        for (std::size_t j = 0; j < tasks_amount; j++) {
            sizes.push_back({j, std::rand() % 100 + 1});
        }
        test_against_exhaustive_search(sizes, agent_amount);
    }
}

BOOST_AUTO_TEST_SUITE_END()