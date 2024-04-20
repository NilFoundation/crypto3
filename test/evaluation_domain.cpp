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

#define BOOST_TEST_MODULE fft_evaluation_domain_test

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>
#include <cstdint>
#include <algorithm>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>

#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/algebra/fields/goldilocks64/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/goldilocks64.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/coset.hpp>
#include <nil/crypto3/math/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/math/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/math/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/math/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/math/domains/step_radix2_domain.hpp>

#include <nil/crypto3/math/algorithms/make_evaluation_domain.hpp>

#include <nil/crypto3/math/polynomial/evaluate.hpp>

#include <typeinfo>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::math;

/**
 * Note: Templatized type referenced with FieldType (instead of canonical FieldType)
 * https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#typed-tests
 */

template<typename FieldType>
void test_fft() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);

    domain->fft(a);

    std::vector<value_type> idx(m);

    for (std::size_t i = 0; i < m; i++) {
        idx[i] = domain->get_domain_element(i);
    }

    std::cout << "FFT: key = " << typeid(*domain).name() << std::endl;
    for (std::size_t i = 0; i < m; i++) {
        value_type e = evaluate_polynomial(f, idx[i], m);
        std::cout << "idx[" << i << "] = " << idx[i].data << std::endl;
        std::cout << "e = " << e.data << std::endl;
        BOOST_CHECK_EQUAL(e.data, a[i].data);
    }
    std::cout << "is_basic_radix2_domain = " << detail::is_basic_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_extended_radix2_domain = " << detail::is_extended_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_step_radix2_domain = " << detail::is_step_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_geometric_sequence_domain = " << detail::is_geometric_sequence_domain<FieldType>(m) << std::endl;
    std::cout << "is_arithmetic_sequence_domain = " << detail::is_arithmetic_sequence_domain<FieldType>(m) << std::endl;
}

template<typename FieldType>
void test_fft_performance(std::string field_name, size_t poly_size, size_t domain_size) {
    typedef typename FieldType::value_type value_type;

    std::vector<value_type> f;

    for (std::size_t i = 0; i < poly_size; ++i) {
        f.push_back(nil::crypto3::algebra::random_element<FieldType>());
    }

    std::shared_ptr<evaluation_domain<FieldType>> domain = make_evaluation_domain<FieldType>(domain_size);

    std::vector<value_type> a(f);

    std::chrono::time_point<std::chrono::high_resolution_clock> start(std::chrono::high_resolution_clock::now());

    size_t SAMPLES = 20;

    for (std::size_t i = 0; i < SAMPLES; ++i) {
        a.resize(poly_size);
        domain->fft(a);
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::high_resolution_clock::now() - start);

    size_t time = elapsed.count() / SAMPLES / 1000 / 1000;
    std::cout << "FFT on " << field_name << " of poly size " << poly_size << " and domain size " << domain_size << " took: " << std::fixed << std::setprecision(3)
        << time / 1000 << " sec " << time % 1000  << " ms" << std::endl;
}

template<typename FieldType>
void test_inverse_fft_of_fft() {
    typedef typename FieldType::value_type value_type;
    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);
    domain->fft(a);
    domain->inverse_fft(a);

    std::cout << "inverse FFT of FFT: key = " << typeid(*domain).name() << std::endl;
    for (std::size_t i = 0; i < m; i++) {
        std::cout << "a[" << i << "] = " << a[i].data << std::endl;
        BOOST_CHECK_EQUAL(f[i].data, a[i].data);
    }
}

template<typename FieldType>
void test_inverse_coset_ftt_of_coset_fft() {
    typedef typename FieldType::value_type value_type;
    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    value_type coset = value_type(fields::arithmetic_params<FieldType>::multiplicative_generator);

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);
    multiply_by_coset(a, coset);
    domain->fft(a);
    domain->inverse_fft(a);
    multiply_by_coset(a, coset.inversed());

    for (std::size_t i = 0; i < m; i++) {
        BOOST_CHECK_EQUAL(f[i].data, a[i].data);
    }
}

template<typename FieldType>
void test_lagrange_coefficients() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a;
    a = domain->evaluate_all_lagrange_polynomials(t);

    std::cout << "LagrangeCoefficients: key = " << typeid(*domain).name() << std::endl;
    std::vector<value_type> d(m);
    for (std::size_t i = 0; i < m; i++) {
        d[i] = domain->get_domain_element(i);
        std::cout << "d[" << i << "] = " << d[i].data << std::endl;
    }

    for (std::size_t i = 0; i < m; i++) {
        value_type e = evaluate_lagrange_polynomial(d, t, m, i);
        BOOST_CHECK_EQUAL(e.data, a[i].data);
        std::cout << "e = " << e.data << std::endl;
    }
}

template<typename FieldType>
void test_compute_z() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    domain = make_evaluation_domain<FieldType>(m);

    value_type a;
    a = domain->compute_vanishing_polynomial(t);

    value_type Z = value_type::one();
    std::cout << "ComputeZ: key = " << typeid(*domain).name() << std::endl;
    for (std::size_t i = 0; i < m; i++) {
        Z *= (t - domain->get_domain_element(i));
        std::cout << "Z = " << Z.data << std::endl;
    }

    BOOST_CHECK_EQUAL(Z.data, a.data);
}

template<typename FieldType, typename GroupType, typename EvaluationDomainType, typename GroupEvaluationDomainType>
void test_fft_curve_elements() {
    typedef typename GroupType::value_type value_type;
    typedef typename FieldType::value_type field_value_type;

    std::size_t m = 4;

    // Make sure the results are reproducible.
    std::srand(0);
    std::vector<field_value_type> f(m);
    std::generate(f.begin(), f.end(), std::rand);
    std::vector<value_type> g(m);
    for(std::size_t i = 0; i < m; ++i) {
        g[i] = value_type::one() * f[i];
    }

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain.reset(new EvaluationDomainType(m));

    std::shared_ptr<evaluation_domain<FieldType, value_type>> curve_element_domain;

    curve_element_domain.reset(new GroupEvaluationDomainType(m));

    domain->fft(f);
    curve_element_domain->fft(g);

    BOOST_CHECK_EQUAL(f.size(), g.size());

    for(std::size_t i = 0; i < f.size(); ++i) {
        BOOST_CHECK(f[i] * value_type::one() == g[i]);
    }

    std::cout << "type name " << typeid(EvaluationDomainType).name() << std::endl;
}

template<typename FieldType, typename GroupType, typename EvaluationDomainType, typename GroupEvaluationDomainType>
void test_inverse_fft_curve_elements() {
    typedef typename GroupType::value_type value_type;
    typedef typename FieldType::value_type field_value_type;

    std::size_t m = 4;

    // Make sure the results are reproducible.
    std::srand(0);
    std::vector<field_value_type> f(m);
    std::generate(f.begin(), f.end(), std::rand);
    std::vector<value_type> g(m);
    for(std::size_t i = 0; i < m; ++i) {
        g[i] = value_type::one() * f[i];
    }

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain.reset(new EvaluationDomainType(m));

    std::shared_ptr<evaluation_domain<FieldType, value_type>> curve_element_domain;

    curve_element_domain.reset(new GroupEvaluationDomainType(m));

    domain->inverse_fft(f);
    curve_element_domain->inverse_fft(g);

    BOOST_CHECK_EQUAL(f.size(), g.size());

    for(std::size_t i = 0; i < f.size(); ++i) {
        BOOST_CHECK(f[i] * value_type::one() == g[i]);
    }

    std::cout << "type name " << typeid(EvaluationDomainType).name() << std::endl;
}

template<typename FieldType, typename EvaluationDomainType>
void test_lagrange_coefficients_from_powers(std::size_t m) {
    typedef typename FieldType::value_type field_value_type;

    // Make sure the results are reproducible.
    std::srand(0);
    field_value_type t = std::rand();
    std::vector<field_value_type> t_powers(m);
    t_powers[0] = field_value_type::one();
    for(std::size_t i = 1; i < m; ++i) {
        t_powers[i] = t_powers[i-1] * t;
    }

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain.reset(new EvaluationDomainType(m));

    std::vector<field_value_type> u = domain->evaluate_all_lagrange_polynomials(t);
    std::vector<field_value_type> u_from_powers = domain->evaluate_all_lagrange_polynomials(t_powers.cbegin(), t_powers.cend());

    BOOST_CHECK_EQUAL(u.size(), u_from_powers.size());

    for(std::size_t i = 0; i < u.size(); ++i) {
        BOOST_CHECK(u[i] == u_from_powers[i]);
    }

    std::cout << "type name " << typeid(EvaluationDomainType).name() << std::endl;
}

template<typename FieldType, typename GroupType, typename EvaluationDomainType, typename GroupEvaluationDomainType>
void test_lagrange_coefficients_curve_elements(std::size_t m) {
    typedef typename FieldType::value_type field_value_type;
    typedef typename GroupType::value_type value_type;

    // Make sure the results are reproducible.
    std::srand(0);
    field_value_type t = std::rand();
    std::vector<value_type> t_powers(m);
    t_powers[0] = value_type::one();
    for(std::size_t i = 1; i < m; ++i) {
        t_powers[i] = t_powers[i-1] * t;
    }

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    domain.reset(new EvaluationDomainType(m));

    std::shared_ptr<evaluation_domain<FieldType, value_type>> curve_element_domain;
    curve_element_domain.reset(new GroupEvaluationDomainType(m));

    std::vector<field_value_type> u = domain->evaluate_all_lagrange_polynomials(t);
    std::vector<value_type> u_curve_element = curve_element_domain->evaluate_all_lagrange_polynomials(t_powers.cbegin(), t_powers.cend());

    BOOST_CHECK_EQUAL(u.size(), u_curve_element.size());

    for(std::size_t i = 0; i < u.size(); ++i) {
        BOOST_CHECK(u[i] * value_type::one() == u_curve_element[i]);
    }

    std::cout << "type name " << typeid(EvaluationDomainType).name() << std::endl;
}

template<typename FieldType, typename EvaluationDomainType>
void test_get_vanishing_polynomial(std::size_t m) {
    typedef typename FieldType::value_type field_value_type;

    // Make sure the results are reproducible.
    std::srand(0);
    field_value_type t = std::rand();

    std::shared_ptr<evaluation_domain<FieldType>> domain;

    domain.reset(new EvaluationDomainType(m));

    field_value_type Zt = domain->compute_vanishing_polynomial(t);
    polynomial<field_value_type> Z = domain->get_vanishing_polynomial();
    BOOST_CHECK(Z.evaluate(t) == Zt);

    std::cout << "type name " << typeid(EvaluationDomainType).name() << std::endl;
}

BOOST_AUTO_TEST_SUITE(fft_evaluation_domain_test_suite)

BOOST_AUTO_TEST_CASE(fft) {
    test_fft<fields::bls12<381>>();
    test_fft<fields::mnt4<298>>();
    test_fft<fields::goldilocks64>();
}

BOOST_AUTO_TEST_CASE(fft_perf_test, *boost::unit_test::disabled()) {
    for (int i = 15; i <= 22; ++i) {
        test_fft_performance<fields::bls12_scalar_field<381>>("BLS12<381> Scalar", 1 << i, 1 << i);
    }
}

BOOST_AUTO_TEST_CASE(inverse_fft_to_fft) {
    test_inverse_fft_of_fft<fields::bls12<381>>();
    test_inverse_fft_of_fft<fields::mnt4<298>>();
    test_inverse_fft_of_fft<fields::goldilocks64>();
}

BOOST_AUTO_TEST_CASE(inverse_coset_ftt_to_coset_fft) {
    test_inverse_coset_ftt_of_coset_fft<fields::bls12<381>>();
    test_inverse_coset_ftt_of_coset_fft<fields::mnt4<298>>();
    test_inverse_coset_ftt_of_coset_fft<fields::goldilocks64>();
}

BOOST_AUTO_TEST_CASE(lagrange_coefficients) {
    test_lagrange_coefficients<fields::bls12<381>>();
    test_lagrange_coefficients<fields::mnt4<298>>();
    test_lagrange_coefficients<fields::goldilocks64>();
}

BOOST_AUTO_TEST_CASE(compute_z) {
    test_compute_z<fields::bls12<381>>();
    test_compute_z<fields::mnt4<298>>();
    test_compute_z<fields::goldilocks64>();
}

BOOST_AUTO_TEST_CASE(curve_elements_fft) {
    typedef curves::bls12<381>::scalar_field_type field_type;
    typedef curves::bls12<381>::g1_type<> group_type;
    using group_value_type = group_type::value_type;

    test_fft_curve_elements<field_type,
                            group_type,
                            basic_radix2_domain<field_type>,
                            basic_radix2_domain<field_type, group_value_type>>();
    // not applicable for any m < 100 for this field
    // test_fft_curve_elements<field_type,
    //                         group_type,
    //                         extended_radix2_domain<field_type>,
    //                         extended_radix2_domain<field_type, group_value_type>>();
    test_fft_curve_elements<field_type,
                            group_type,
                            step_radix2_domain<field_type>,
                            step_radix2_domain<field_type, group_value_type>>();
    test_fft_curve_elements<field_type,
                            group_type,
                            geometric_sequence_domain<field_type>,
                            geometric_sequence_domain<field_type, group_value_type>>();
    test_fft_curve_elements<field_type,
                            group_type,
                            arithmetic_sequence_domain<field_type>,
                            arithmetic_sequence_domain<field_type, group_value_type>>();
}

BOOST_AUTO_TEST_CASE(curve_elements_inverse_fft) {
    typedef curves::bls12<381>::scalar_field_type field_type;
    typedef curves::bls12<381>::g1_type<> group_type;
    using group_value_type = group_type::value_type;

    test_inverse_fft_curve_elements<field_type,
                            group_type,
                            basic_radix2_domain<field_type>,
                            basic_radix2_domain<field_type, group_value_type>>();
    // not applicable for any m < 100 for this field
    // test_inverse_fft_curve_elements<field_type,
    //                         group_type,
    //                         extended_radix2_domain<field_type>,
    //                         extended_radix2_domain<field_type, group_value_type>>();
    test_inverse_fft_curve_elements<field_type,
                            group_type,
                            step_radix2_domain<field_type>,
                            step_radix2_domain<field_type, group_value_type>>();
    test_inverse_fft_curve_elements<field_type,
                            group_type,
                            geometric_sequence_domain<field_type>,
                            geometric_sequence_domain<field_type, group_value_type>>();
    test_inverse_fft_curve_elements<field_type,
                            group_type,
                            arithmetic_sequence_domain<field_type>,
                            arithmetic_sequence_domain<field_type, group_value_type>>();
}

BOOST_AUTO_TEST_CASE(lagrange_coefficients_from_powers) {
    typedef curves::bls12<381>::scalar_field_type field_type;

    test_lagrange_coefficients_from_powers<field_type,
                            basic_radix2_domain<field_type>>(4);
    // not applicable for any m < 100 for this field, testing with base field instead
    test_lagrange_coefficients_from_powers<fields::bls12<381>,
                            extended_radix2_domain<fields::bls12<381>>>(4);
    test_lagrange_coefficients_from_powers<field_type,
                            step_radix2_domain<field_type>>(4);
    test_lagrange_coefficients_from_powers<field_type,
                            geometric_sequence_domain<field_type>>(4);
    test_lagrange_coefficients_from_powers<field_type,
                            arithmetic_sequence_domain<field_type>>(4);
}

BOOST_AUTO_TEST_CASE(curve_elements_lagrange_coefficients) {
    typedef curves::bls12<381>::scalar_field_type field_type;
    typedef curves::bls12<381>::g1_type<> group_type;
    using group_value_type = group_type::value_type;

    test_lagrange_coefficients_curve_elements<field_type,
                            group_type,
                            basic_radix2_domain<field_type>,
                            basic_radix2_domain<field_type, group_value_type>>(4);
    // not applicable for any m < 100 for this field
    // test_lagrange_coefficients_curve_elements<field_type,
    //                         group_type,
    //                         extended_radix2_domain<field_type>,
    //                         extended_radix2_domain<field_type, group_value_type>>(4);
    test_lagrange_coefficients_curve_elements<field_type,
                            group_type,
                            step_radix2_domain<field_type>,
                            step_radix2_domain<field_type, group_value_type>>(4);
    test_lagrange_coefficients_curve_elements<field_type,
                            group_type,
                            geometric_sequence_domain<field_type>,
                            geometric_sequence_domain<field_type, group_value_type>>(4);
    test_lagrange_coefficients_curve_elements<field_type,
                            group_type,
                            arithmetic_sequence_domain<field_type>,
                            arithmetic_sequence_domain<field_type, group_value_type>>(4);
}

BOOST_AUTO_TEST_CASE(get_vanishing_polynomial) {
    typedef curves::bls12<381>::scalar_field_type field_type;

    test_get_vanishing_polynomial<field_type,
                            basic_radix2_domain<field_type>>(4);
    // not applicable for any m < 100 for this field, testing with base field instead
    test_get_vanishing_polynomial<fields::bls12<381>,
                            extended_radix2_domain<fields::bls12<381>>>(4);
    test_get_vanishing_polynomial<field_type,
                            step_radix2_domain<field_type>>(4);
    test_get_vanishing_polynomial<field_type,
                            geometric_sequence_domain<field_type>>(4);
    test_get_vanishing_polynomial<field_type,
                            arithmetic_sequence_domain<field_type>>(4);
}

BOOST_AUTO_TEST_SUITE_END()
