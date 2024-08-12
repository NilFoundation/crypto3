//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE multiexpr_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <cstdio>
#include <vector>
#include <chrono>
#include <ctime>

#include <nil/crypto3/algebra/multiexp/multiexp.hpp>
#include <nil/crypto3/algebra/multiexp/policies.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/edwards.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

template<typename GroupType>
using run_result_t = std::pair<long long, std::vector<typename GroupType::value_type>>;

template<typename T>
using test_instances_t = std::vector<std::vector<typename T::value_type>>;

template<typename GroupType>
test_instances_t<GroupType> generate_group_elements(std::size_t count, std::size_t size) {
    // generating a random group element is expensive,
    // so for now we only generate a single one and repeat it
    test_instances_t<GroupType> result(count);

    for (size_t i = 0; i < count; i++) {

        typename GroupType::value_type x =
            random_element<GroupType>();    // djb requires input to be in special form

        for (size_t j = 0; j < size; j++) {
            result[i].push_back(x);
            // result[i].push_back(curve_random_element<GroupType>());
        }
    }

    return result;
}

template<typename FieldType>
test_instances_t<FieldType> generate_scalars(std::size_t count, std::size_t size) {
    // we use SHA512_rng because it is much faster than
    // FieldType::random_element()
    test_instances_t<FieldType> result(count);

    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < size; j++) {
            result[i].push_back(random_element<FieldType>());
        }
    }

    return result;
}

long long get_nsec_time() {
    auto timepoint = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(timepoint.time_since_epoch()).count();
}

template<typename GroupType, typename FieldType, typename MultiexpMethod>
run_result_t<GroupType>
    profile_multiexp(test_instances_t<GroupType> group_elements, test_instances_t<FieldType> scalars) {
    long long start_time = get_nsec_time();

    std::vector<typename GroupType::value_type> answers;
    for (size_t i = 0; i < group_elements.size(); i++) {
        answers.push_back(multiexp<MultiexpMethod>(group_elements[i].cbegin(), group_elements[i].cend(),
                                                   scalars[i].cbegin(), scalars[i].cend(), 1));
    }

    long long time_delta = get_nsec_time() - start_time;

    return run_result_t<GroupType>(time_delta, answers);
}

template<typename GroupType, typename FieldType>
void print_performance_csv(size_t expn_start, std::size_t expn_end_fast, std::size_t expn_end_naive,
                           bool compare_answers) {
    for (size_t expn = expn_start; expn <= expn_end_fast; expn++) {
        printf("%ld", expn);
        fflush(stdout);

        test_instances_t<GroupType> group_elements = generate_group_elements<GroupType>(10, 1 << expn);
        test_instances_t<FieldType> scalars = generate_scalars<FieldType>(10, 1 << expn);

        run_result_t<GroupType> result_bos_coster =
            profile_multiexp<GroupType, FieldType, policies::multiexp_method_bos_coster>(group_elements, scalars);
        printf("\t%lld", result_bos_coster.first);
        fflush(stdout);

        run_result_t<GroupType> result_djb =
            profile_multiexp<GroupType, FieldType, policies::multiexp_method_BDLO12>(group_elements, scalars);
        printf("\t%lld", result_djb.first);
        fflush(stdout);

        if (compare_answers && (result_bos_coster.second != result_djb.second)) {
            fprintf(stderr, "Answers NOT MATCHING (bos coster != djb)\n");
        }

        if (expn <= expn_end_naive) {
            run_result_t<GroupType> result_naive =
                profile_multiexp<GroupType, FieldType, policies::multiexp_method_naive_plain>(group_elements, scalars);
            printf("\t%lld", result_naive.first);
            fflush(stdout);

            if (compare_answers && (result_bos_coster.second != result_naive.second)) {
                fprintf(stderr, "Answers NOT MATCHING (bos coster != naive)\n");
            }
        }

        printf("\n");
    }
}

BOOST_AUTO_TEST_SUITE(multiexp_test_suite)

BOOST_AUTO_TEST_CASE(multiexp_test_case) {

    std::cout << "Testing BLS12-381 G1" << std::endl;
    print_performance_csv<curves::bls12<381>::g1_type<>, curves::bls12<381>::scalar_field_type>(2, 12, 14, true);

    std::cout << "Testing BLS12-381 G2" << std::endl;
    print_performance_csv<curves::bls12<381>::g2_type<>, curves::bls12<381>::scalar_field_type>(2, 12, 14, true);
}

BOOST_AUTO_TEST_SUITE_END()
