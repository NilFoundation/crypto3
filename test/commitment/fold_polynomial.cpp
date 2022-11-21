//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#define BOOST_TEST_MODULE fold_polynomial_test

#include <string>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/polynomial/polynomial.hpp>
#include <nil/crypto3/math/polynomial/polynomial_dfs.hpp>
#include <nil/crypto3/math/polynomial/lagrange_interpolation.hpp>
#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/zk/commitments/detail/polynomial/fold_polynomial.hpp>

using namespace nil::crypto3;

template<typename CurveType>
void test_fold_polynomial() {

    using FieldType = typename CurveType::base_field_type;

    constexpr static const std::size_t d = 4;

    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::size_t d_log = boost::static_log2<d>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(d_log, 1);

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 3};

    typename FieldType::value_type omega = D[0]->get_domain_element(1);

    typename FieldType::value_type x_next = q.evaluate(omega);
    typename FieldType::value_type alpha = algebra::random_element<FieldType>();

    math::polynomial<typename FieldType::value_type> f_next =
        zk::commitments::detail::fold_polynomial<FieldType>(f, alpha);

    BOOST_CHECK_EQUAL(f_next.degree(), f.degree() / 2);
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> interpolation_points {
        std::make_pair(omega, f.evaluate(omega)),
        std::make_pair(-omega, f.evaluate(-omega)),
    };

    math::polynomial<typename FieldType::value_type> interpolant = math::lagrange_interpolation(interpolation_points);
    typename FieldType::value_type x1 = interpolant.evaluate(alpha);
    typename FieldType::value_type x2 = f_next.evaluate(x_next);
    BOOST_CHECK(x1 == x2);
}

template<typename CurveType>
void test_fold_polynomial_dfs() {
    using FieldType = typename CurveType::base_field_type;

    constexpr static const std::size_t d = 4;

    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    std::size_t d_log = boost::static_log2<d>::value;
    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> D =
        math::calculate_domain_set<FieldType>(d_log, 2);

    math::polynomial<typename FieldType::value_type> f = {1, 3, 4, 3};

    typename FieldType::value_type omega = D[0]->get_domain_element(1);

    typename FieldType::value_type x_next = q.evaluate(omega);
    typename FieldType::value_type alpha = algebra::random_element<FieldType>();

    math::polynomial_dfs<typename FieldType::value_type> f_dfs(3, D[0]->size(), 0);
    std::vector<typename FieldType::value_type> f_vector(f.size());
    for (std::size_t i = 0; i < f.size(); i++) {
        f_vector[i] = f[i];
    }
    D[0]->fft(f_vector);
    for (std::size_t i = 0; i < f.size(); i++) {
        f_dfs[i] = f_vector[i];
    }

    math::polynomial_dfs<typename FieldType::value_type> f_next_dfs =
        zk::commitments::detail::fold_polynomial<FieldType>(f_dfs, alpha, D[0]);
    std::vector<typename FieldType::value_type> f_next_vector(f_next_dfs.begin(), f_next_dfs.end());
    D[1]->inverse_fft(f_next_vector);
    math::polynomial<typename FieldType::value_type> f_next(f_next_vector.size());
    for (std::size_t i = 0; i < f_next_vector.size(); i++) {
        f_next[i] = f_next_vector[i];
    }

    BOOST_CHECK_EQUAL(f_next.degree(), f.degree() / 2);
    std::vector<std::pair<typename FieldType::value_type, typename FieldType::value_type>> interpolation_points {
        std::make_pair(omega, f.evaluate(omega)),
        std::make_pair(-omega, f.evaluate(-omega)),
    };

    math::polynomial<typename FieldType::value_type> interpolant = math::lagrange_interpolation(interpolation_points);
    typename FieldType::value_type x1 = interpolant.evaluate(alpha);
    typename FieldType::value_type x2 = f_next.evaluate(x_next);
    BOOST_CHECK(x1 == x2);
}

BOOST_AUTO_TEST_SUITE(fold_polynomial_test_suite)

BOOST_AUTO_TEST_CASE(fold_polynomial_test) {
    test_fold_polynomial<algebra::curves::mnt4<298>>();

    test_fold_polynomial<algebra::curves::pallas>();

    test_fold_polynomial<algebra::curves::vesta>();
}

BOOST_AUTO_TEST_CASE(fold_polynomial_dfs_test) {

    test_fold_polynomial_dfs<algebra::curves::mnt4<298>>();

    test_fold_polynomial_dfs<algebra::curves::pallas>();

    test_fold_polynomial_dfs<algebra::curves::vesta>();
}

BOOST_AUTO_TEST_SUITE_END()