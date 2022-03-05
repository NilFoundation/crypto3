//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@nil.foundation>
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

#define BOOST_TEST_MODULE polynomial_dft_arithmetic_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/math/polynomial/polynomial_dft.hpp>
#include <nil/crypto3/math/polynomial/polynomial.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

typedef fields::bls12_fr<381> FieldType;

BOOST_AUTO_TEST_SUITE(polynomial_dft_constructor_test_suite)

// BOOST_AUTO_TEST_CASE(polynomial_dft_constructor) {
//
//     polynomial_dft<typename FieldType::value_type> a(FieldType::value_type::one(), 5);
//     polynomial_dft<typename FieldType::value_type> a_expected = {0, 0, 0, 0, 0, 1};
//
//     for (std::size_t i = 0; i < a_expected.size(); i++) {
//         BOOST_CHECK_EQUAL(a_expected[i].data, a[i].data);
//     }
// }
BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_CASE(polynomial_recover_same_degree) {
    polynomial_dft<typename FieldType::value_type> a = {
        8,
        {0x37, 0x6C17ABF513DFFC886A7F49F970801792C825CFDD829870DC60E8DA51F53633_cppui253,
         0x73EDA753299D7D3ED0CB3E52336E8625A78AA3D929CB5BFEFFEEFFFEFFFFFFFD_cppui253,
         0x53B09574717196328488C7990499B10ABA0C038C321BF5B1C0D1C5A4E10C7330_cppui253,
         0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFEE_cppui253,
         0x73818FA734899D485AE48BE74C1F3B0838E37E245E69C38E23991724AE0AC9C4_cppui253,
         0x9626E99B5D63351DFAC330029D63300000010FFFFFFFFFFFC_cppui253,
         0x203D11DEB82BE718FE9BDD45C91A43E021C3A08591F4664D3F343A5A1EF38CC7_cppui253}};
    polynomial<typename FieldType::value_type> c_res = {1, 3, 4, 25, 6, 7, 7, 2};
    polynomial<typename FieldType::value_type> c = a;
    for (std::size_t i = 0; i < c.size(); i++) {
        BOOST_CHECK_EQUAL(c_res[i].data, c[i].data);
    }
}

BOOST_AUTO_TEST_SUITE(polynomial_dft_addition_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_addition_equal) {
    polynomial_dft<typename FieldType::value_type> a = {
        8,
        {0x37, 0x6C17ABF513DFFC886A7F49F970801792C825CFDD829870DC60E8DA51F53633_cppui253,
         0x73EDA753299D7D3ED0CB3E52336E8625A78AA3D929CB5BFEFFEEFFFEFFFFFFFD_cppui253,
         0x53B09574717196328488C7990499B10ABA0C038C321BF5B1C0D1C5A4E10C7330_cppui253,
         0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFEFFFFFFEE_cppui253,
         0x73818FA734899D485AE48BE74C1F3B0838E37E245E69C38E23991724AE0AC9C4_cppui253,
         0x9626E99B5D63351DFAC330029D63300000010FFFFFFFFFFFC_cppui253,
         0x203D11DEB82BE718FE9BDD45C91A43E021C3A08591F4664D3F343A5A1EF38CC7_cppui253}};
    typename FieldType::value_type xt = 2;
    std::cout << "!!!" << a.evaluate(xt).data << std::endl;
    size_t zerg_c = 8;
    typename FieldType::value_type omega = unity_root<FieldType>(zerg_c);
    std::vector<typename FieldType::value_type> tmp(a.begin(), a.end());
    detail::basic_serial_radix2_fft<FieldType>(tmp, omega.inversed());
    typename FieldType::value_type sconst = typename FieldType::value_type(zerg_c).inversed();
    std::transform(tmp.begin(),
                   tmp.end(),
                   tmp.begin(),
                   std::bind(std::multiplies<typename FieldType::value_type>(), sconst, std::placeholders::_1));

    for (std::size_t i = 0; i < tmp.size(); ++i) {
        std::cout << tmp[i].data << std::endl;
    }

    //    polynomial_dft<typename FieldType::value_type> b =
    //    {0x12AB655E9A2CA55660B44D1E5C37B00159AA76FED00000010A11800000000001_cppui253}; polynomial_dft<typename
    //    FieldType::value_type> c(1, FieldType::value_type::zero());
    //
    ////    c = a + b;
    //
    //    polynomial_dft<typename FieldType::value_type> c_ans = {10, 6, 15, 39, 13, 8, 12, 10};
    //
    //    for (std::size_t i = 0; i < c.size(); ++i) {
    //        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
    //    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_dft_subtraction_test_suite)
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_equal) {
//
//    polynomial_dft<typename FieldType::value_type> a = {8, {1, 3, 4, 25, 6, 7, 7, 2}};
//    polynomial_dft<typename FieldType::value_type> b = {8, {9, 3, 11, 14, 7, 1, 5, 8}};
//    polynomial_dft<typename FieldType::value_type> c(8, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {-8, 0, -7, 11, -1, 6, 2, -6}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_long_a) {
//
//    polynomial_dft<typename FieldType::value_type> a = {8, {1, 3, 4, 25, 6, 7, 7, 2}};
//    polynomial_dft<typename FieldType::value_type> b = {5, {9, 3, 11, 14, 7}};
//    polynomial_dft<typename FieldType::value_type> c(8, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {-8, 0, -7, 11, -1, 7, 7, 2}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_long_b) {
//
//    polynomial_dft<typename FieldType::value_type> a = {5, {1, 3, 4, 25, 6}};
//    polynomial_dft<typename FieldType::value_type> b = {8, {9, 3, 11, 14, 7, 1, 5, 8}};
//    polynomial_dft<typename FieldType::value_type> c(8, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {-8, 0, -7, 11, -1, -1, -5, -8}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_zero_a) {
//
//    polynomial_dft<typename FieldType::value_type> a = {3, {0, 0, 0}};
//    polynomial_dft<typename FieldType::value_type> b = {8, {1, 3, 4, 25, 6, 7, 7, 2}};
//    polynomial_dft<typename FieldType::value_type> c(8, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {-1, -3, -4, -25, -6, -7, -7, -2}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_zero_b) {
//
//    polynomial_dft<typename FieldType::value_type> a = {8, {1, 3, 4, 25, 6, 7, 7, 2}};
//    polynomial_dft<typename FieldType::value_type> b = {3, {0, 0, 0}};
//    polynomial_dft<typename FieldType::value_type> c(8, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {1, 3, 4, 25, 6, 7, 7, 2}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_subtraction_degree_not_equal_points_count) {
//
//    polynomial_dft<typename FieldType::value_type> a = {5, {1, 3, 4, 25, 6, 7, 7, 2}};
//    polynomial_dft<typename FieldType::value_type> b = {3, {9, 3, 11, 14, 7, 1, 5, 8}};
//    polynomial_dft<typename FieldType::value_type> c(5, 1, FieldType::value_type::zero());
//
//    c = a - b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {5, {-8, 0, -7, 11, -1, 6, 2, -6}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//    BOOST_CHECK_EQUAL(c.degree(), c_ans.degree());
//}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_dft_multiplication_test_suite)

// BOOST_AUTO_TEST_CASE(polynomial_dft_multiplication_long_a) {
//
//    polynomial_dft<typename FieldType::value_type> a = {6, {5, 0, 0, 13, 0, 1}};
//    polynomial_dft<typename FieldType::value_type> b = {3, {13, 0, 1}};
//    polynomial_dft<typename FieldType::value_type> c(9, 1, FieldType::value_type::zero());
//
//    c = a * b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {8, {65, 0, 5, 169, 0, 26, 0, 1}};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_multiplication_long_b) {
//
//    polynomial_dft<typename FieldType::value_type> a = {13, 0, 1};
//    polynomial_dft<typename FieldType::value_type> b = {5, 0, 0, 13, 0, 1};
//    polynomial_dft<typename FieldType::value_type> c(1, FieldType::value_type::zero());
//
//    c = a * b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {65, 0, 5, 169, 0, 26, 0, 1};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_multiplication_zero_a) {
//
//    polynomial_dft<typename FieldType::value_type> a = {0};
//    polynomial_dft<typename FieldType::value_type> b = {5, 0, 0, 13, 0, 1};
//    polynomial_dft<typename FieldType::value_type> c(1, FieldType::value_type::zero());
//
//    c = a * b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {0};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//}
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_multiplication_zero_b) {
//
//    polynomial_dft<typename FieldType::value_type> a = {5, 0, 0, 13, 0, 1};
//    polynomial_dft<typename FieldType::value_type> b = {0};
//    polynomial_dft<typename FieldType::value_type> c(1, FieldType::value_type::zero());
//
//    c = a * b;
//
//    polynomial_dft<typename FieldType::value_type> c_ans = {0};
//
//    for (std::size_t i = 0; i < c.size(); i++) {
//        BOOST_CHECK_EQUAL(c_ans[i].data, c[i].data);
//    }
//}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(polynomial_dft_division_test_suite)
//
// BOOST_AUTO_TEST_CASE(polynomial_dft_division) {
//
//    polynomial_dft<typename FieldType::value_type> a = {5, 0, 0, 13, 0, 1};
//    polynomial_dft<typename FieldType::value_type> b = {13, 0, 1};
//
//    polynomial_dft<typename FieldType::value_type> Q(1, FieldType::value_type::zero());
//    polynomial_dft<typename FieldType::value_type> R(1, FieldType::value_type::zero());
//
//    Q = a / b;
////    R = a % b;
//
//    polynomial_dft<typename FieldType::value_type> Q_ans = {0, 0, 0, 1};
//    polynomial_dft<typename FieldType::value_type> R_ans = {5};
//
//    for (std::size_t i = 0; i < Q.size(); i++) {
//        BOOST_CHECK_EQUAL(Q_ans[i].data, Q[i].data);
//    }
//    for (std::size_t i = 0; i < R.size(); i++) {
//        BOOST_CHECK_EQUAL(R_ans[i].data, R[i].data);
//    }
//}

BOOST_AUTO_TEST_SUITE_END()