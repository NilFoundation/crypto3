//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
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

#define BOOST_TEST_MODULE polynomial_lagrange_interpolation_test

#include <vector>
#include <cstdint>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

BOOST_AUTO_TEST_SUITE(polynomial_lagrange_interpolation_test_suite)

BOOST_AUTO_TEST_CASE(polynomial_lagrange_interpolation_manual_test) {
    using field_type = fields::bls12_fr<381>;
    using integral_type = typename field_type::integral_type;

    std::vector<std::pair<typename field_type::value_type, typename field_type::value_type>> points {
        std::make_pair(integral_type("4183765791887380684480255226180760560865026071039013052010193328713615339463"),
                       integral_type("31102318824077738286102042205447650848522120060321475185704476031394567067018")),
        std::make_pair(integral_type("41539907117522402745491644732028924977664979905128012893033887353901692293856"),
                       integral_type("28448837760680269221266237156411444765443870003701617079904611621539413948874")),
        std::make_pair(integral_type("40744787028008542045211760826403355424425002249388314752473792073759989008118"),
                       integral_type("21652586267347562689641261610058946541341503152256840037277559314528271150653"))};
    polynomial<typename field_type::value_type> ans = lagrange_interpolation(points);

    polynomial<typename field_type::value_type> ans_expected = {
        integral_type("45863909754770953574941211132560772200443894513098009385289015884407326107132"),
        integral_type("306400884220968022577340188138333996135439223138113708607130720467290203462"),
        integral_type("40785886772544473963190998835184144050681147583222663910965803442251397137695")};

    BOOST_CHECK_EQUAL(ans.size(), ans_expected.size());
    for (std::size_t i = 0; i < ans.size(); ++i) {
        BOOST_CHECK(ans[i] == ans_expected[i]);
    }
}

BOOST_AUTO_TEST_CASE(polynomial_lagrange_interpolation_random_test) {
    using field_type = fields::bls12_fr<381>;
    auto one = field_type::value_type::one();

    std::size_t n = std::rand() % 50 + 1;
    std::vector<typename field_type::value_type> p_coeffs(2 * n);
    std::vector<typename field_type::value_type> pts(n);
    std::vector<typename field_type::value_type> evals(n);
    for (std::size_t i = 0; i < n; ++i) {
        p_coeffs[i] = nil::crypto3::algebra::random_element<field_type>();
        p_coeffs[n + i] = nil::crypto3::algebra::random_element<field_type>();
        pts[i] = i * one;
    }
    polynomial<typename field_type::value_type> p = {p_coeffs.begin(), p_coeffs.end()};
    std::vector<std::pair<typename field_type::value_type, typename field_type::value_type>> points;
    for (std::size_t i = 0; i < n; ++i) {
        evals[i] = p.evaluate(pts[i]);
        points.push_back(std::make_pair(pts[i], evals[i]));
    }

    polynomial<typename field_type::value_type> ans = lagrange_interpolation(points);

    for (std::size_t i = 0; i < ans.size(); ++i) {
        BOOST_CHECK(ans.evaluate(points[i].first) == points[i].second);
    }
}

BOOST_AUTO_TEST_SUITE_END()
