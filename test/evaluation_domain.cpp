//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
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

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>

#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>

#include <nil/crypto3/fft/coset.hpp>
#include <nil/crypto3/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/step_radix2_domain.hpp>

#include <nil/crypto3/fft/make_evaluation_domain.hpp>

#include <nil/crypto3/fft/polynomial_arithmetic/naive_evaluate.hpp>

#include <typeinfo>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::fft;

/**
 * Note: Templatized type referenced with FieldType (instead of canonical FieldType)
 * https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#typed-tests
 */

template<typename FieldType>
void test_fft() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    // for (int key = 0; key < 5; key++) {
    /*if (key == 0)
        domain.reset(new basic_radix2_domain<FieldType>(m));
    else if (key == 1)
        domain.reset(new extended_radix2_domain<FieldType>(m));
    else if (key == 2)
        domain.reset(new step_radix2_domain<FieldType>(m));
    else if (key == 3)
        domain.reset(new geometric_sequence_domain<FieldType>(m));
    else if (key == 4)
        domain.reset(new arithmetic_sequence_domain<FieldType>(m));*/

    domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);

    domain->FFT(a);

    std::vector<value_type> idx(m);

    for (std::size_t i = 0; i < m; i++) {
        idx[i] = domain->get_domain_element(i);
    }

    std::cout << "FFT: key = " << typeid(*domain).name() << std::endl;
    for (std::size_t i = 0; i < m; i++) {
        value_type e = evaluate_polynomial(m, f, idx[i]);
        std::cout << "idx[" << i << "] = " << idx[i].data << std::endl;
        std::cout << "e = " << e.data << std::endl;
        BOOST_CHECK_EQUAL(e.data, a[i].data);
        // std::cout << e.data << " == " << a[i].data << std::endl;
    }
    // }
    std::cout << "is_basic_radix2_domain = " << detail::is_basic_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_extended_radix2_domain = " << detail::is_extended_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_step_radix2_domain = " << detail::is_step_radix2_domain<FieldType>(m) << std::endl;
    std::cout << "is_geometric_sequence_domain = " << detail::is_geometric_sequence_domain<FieldType>(m) << std::endl;
    std::cout << "is_arithmetic_sequence_domain = " << detail::is_arithmetic_sequence_domain<FieldType>(m) << std::endl;
}

template<typename FieldType>
void test_inverse_fft_of_fft() {
    typedef typename FieldType::value_type value_type;
    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    // for (int key = 0; key < 5; key++) {
    /*if (key == 0)
        domain.reset(new basic_radix2_domain<FieldType>(m));
    else if (key == 1)
        domain.reset(new extended_radix2_domain<FieldType>(m));
    else if (key == 2)
        domain.reset(new step_radix2_domain<FieldType>(m));
    else if (key == 3)
        domain.reset(new geometric_sequence_domain<FieldType>(m));
    else if (key == 4)
        domain.reset(new arithmetic_sequence_domain<FieldType>(m));*/

    domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);
    domain->FFT(a);
    domain->iFFT(a);

    std::cout << "inverse FFT of FFT: key = " << typeid(*domain).name() << std::endl;
    for (std::size_t i = 0; i < m; i++) {
        std::cout << "a[" << i << "] = " << a[i].data << std::endl;
        BOOST_CHECK_EQUAL(f[i].data, a[i].data);
        // std::cout << f[i].data << " == " << a[i].data << std::endl;
    }
    // }
}

template<typename FieldType>
void test_inverse_coset_ftt_of_coset_fft() {
    typedef typename FieldType::value_type value_type;
    const std::size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    value_type coset = value_type(fields::arithmetic_params<FieldType>::multiplicative_generator);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    // for (int key = 0; key < 3; key++) {
    /*if (key == 0)
        domain.reset(new basic_radix2_domain<FieldType>(m));
    else if (key == 1)
        domain.reset(new extended_radix2_domain<FieldType>(m));
    else if (key == 2)
        domain.reset(new step_radix2_domain<FieldType>(m));
    else if (key == 3)
        domain.reset(new geometric_sequence_domain<FieldType>(m));
    else if (key == 4)
        domain.reset(new arithmetic_sequence_domain<FieldType>(m));*/

    domain = make_evaluation_domain<FieldType>(m);

    std::vector<value_type> a(f);
    multiply_by_coset(a, coset);
    domain->FFT(a);
    domain->iFFT(a);
    multiply_by_coset(a, coset.inversed());

    for (std::size_t i = 0; i < m; i++) {
        BOOST_CHECK_EQUAL(f[i].data, a[i].data);
        // std::cout << f[i].data << " == " << a[i].data << std::endl;
    }
    // }
}

template<typename FieldType>
void test_lagrange_coefficients() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    // for (int key = 0; key < 5; key++) {
    /*if (key == 0)
        domain.reset(new basic_radix2_domain<FieldType>(m));
    else if (key == 1)
        domain.reset(new extended_radix2_domain<FieldType>(m));
    else if (key == 2)
        domain.reset(new step_radix2_domain<FieldType>(m));
    else if (key == 3)
        domain.reset(new geometric_sequence_domain<FieldType>(m));
    else if (key == 4)
        domain.reset(new arithmetic_sequence_domain<FieldType>(m));*/

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
        value_type e = evaluate_lagrange_polynomial(m, d, t, i);
        // printf("%ld == %ld\n", e.as_ulong(), a[i].as_ulong());
        BOOST_CHECK_EQUAL(e.data, a[i].data);
        std::cout << "e = " << e.data << std::endl;
    }
    // }
}

template<typename FieldType>
void test_compute_z() {
    typedef typename FieldType::value_type value_type;

    const std::size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    // for (int key = 0; key < 5; key++) {
    /*if (key == 0)
        domain.reset(new basic_radix2_domain<FieldType>(m));
    else if (key == 1)
        domain.reset(new extended_radix2_domain<FieldType>(m));
    else if (key == 2)
        domain.reset(new step_radix2_domain<FieldType>(m));
    else if (key == 3)
        domain.reset(new geometric_sequence_domain<FieldType>(m));
    else if (key == 4)
        domain.reset(new arithmetic_sequence_domain<FieldType>(m));*/

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
    // std::cout << Z.data << " == " << a.data << std::endl;
    // }
}

BOOST_AUTO_TEST_SUITE(fft_evaluation_domain_test_suite)

BOOST_AUTO_TEST_CASE(fft) {
    // test_fft<fields::bls12<381>>();
    test_fft<fields::mnt4_fr<298>>();
}

BOOST_AUTO_TEST_CASE(inverse_fft_to_fft) {
    // test_inverse_fft_of_fft<fields::bls12<381>>();
    test_inverse_fft_of_fft<fields::mnt4_fr<298>>();
}

BOOST_AUTO_TEST_CASE(inverse_coset_ftt_to_coset_fft) {
    // test_inverse_coset_ftt_of_coset_fft<fields::bls12<381>>();
    test_inverse_coset_ftt_of_coset_fft<fields::mnt4_fr<298>>();
}

BOOST_AUTO_TEST_CASE(lagrange_coefficients) {
    // test_lagrange_coefficients<fields::bls12<381>>();
    test_lagrange_coefficients<fields::mnt4_fr<298>>();
}

BOOST_AUTO_TEST_CASE(compute_z) {
    // test_compute_z<fields::bls12<381>>();
    test_compute_z<fields::mnt4_fr<298>>();
}

BOOST_AUTO_TEST_SUITE_END()
