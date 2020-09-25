//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE fft_evaluation_domain_test

#include <boost/test/unit_test.hpp>

#include <memory>
#include <vector>
#include <cstdint>

#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>

#include <nil/crypto3/fft/domains/arithmetic_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/basic_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/extended_radix2_domain.hpp>
#include <nil/crypto3/fft/domains/geometric_sequence_domain.hpp>
#include <nil/crypto3/fft/domains/step_radix2_domain.hpp>

#include <nil/crypto3/fft/polynomial_arithmetic/naive_evaluate.hpp>

using namespace nil::crypto3::algebra;
using namespace nil::crypto3::fft;

/**
 * Note: Templatized type referenced with FieldType (instead of canonical FieldType)
 * https://github.com/google/googletest/blob/master/googletest/docs/AdvancedGuide.md#typed-tests
 */

template<typename FieldType>
void test_fft() {
    using value_type = typename FieldType::value_type;

    const size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    for (int key = 0; key < 5; key++) {
        try {
            if (key == 0)
                domain.reset(new basic_radix2_domain<FieldType>(m));
            else if (key == 1)
                domain.reset(new extended_radix2_domain<FieldType>(m));
            else if (key == 2)
                domain.reset(new step_radix2_domain<FieldType>(m));
            else if (key == 3)
                domain.reset(new geometric_sequence_domain<FieldType>(m));
            else if (key == 4)
                domain.reset(new arithmetic_sequence_domain<FieldType>(m));

            std::vector<value_type> a(f);
            domain->FFT(a);

            std::vector<value_type> idx(m);
            for (size_t i = 0; i < m; i++) {
                idx[i] = domain->get_domain_element(i);
            }

            for (size_t i = 0; i < m; i++) {
                value_type e = evaluate_polynomial(m, f, idx[i]);
                BOOST_CHECK(e == a[i]);
            }
        } catch (DomainSizeException &e) {
            printf("%s - skipping\n", e.what());
        } catch (InvalidSizeException &e) {
            printf("%s - skipping\n", e.what());
        }
    }
}

template<typename FieldType>
void test_inverse_fft_to_fft() {
    using value_type = typename FieldType::value_type;
    const size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    for (int key = 0; key < 5; key++) {
        try {
            if (key == 0)
                domain.reset(new basic_radix2_domain<FieldType>(m));
            else if (key == 1)
                domain.reset(new extended_radix2_domain<FieldType>(m));
            else if (key == 2)
                domain.reset(new step_radix2_domain<FieldType>(m));
            else if (key == 3)
                domain.reset(new geometric_sequence_domain<FieldType>(m));
            else if (key == 4)
                domain.reset(new arithmetic_sequence_domain<FieldType>(m));

            std::vector<value_type> a(f);
            domain->FFT(a);
            domain->iFFT(a);

            for (size_t i = 0; i < m; i++) {
                BOOST_CHECK(f[i] == a[i]);
            }
        } catch (const DomainSizeException &e) {
            printf("%s - skipping\n", e.what());
        } catch (const InvalidSizeException &e) {
            printf("%s - skipping\n", e.what());
        }
    }
}

template<typename FieldType>
void test_inverse_coset_ftt_to_coset_fft() {
    using value_type = typename FieldType::value_type;
    const size_t m = 4;
    std::vector<value_type> f = {2, 5, 3, 8};

    value_type coset = value_type(fields::arithmetic_params<FieldType>::multiplicative_generator);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    for (int key = 0; key < 3; key++) {
        try {
            if (key == 0)
                domain.reset(new basic_radix2_domain<FieldType>(m));
            else if (key == 1)
                domain.reset(new extended_radix2_domain<FieldType>(m));
            else if (key == 2)
                domain.reset(new step_radix2_domain<FieldType>(m));
            else if (key == 3)
                domain.reset(new geometric_sequence_domain<FieldType>(m));
            else if (key == 4)
                domain.reset(new arithmetic_sequence_domain<FieldType>(m));

            std::vector<value_type> a(f);
            multiply_by_coset(a, coset);
            domain->FFT(a, coset);
            domain->iFFT(a, coset);
            multiply_by_coset(a, coset.inversed());

            for (size_t i = 0; i < m; i++) {
                BOOST_CHECK(f[i] == a[i]);
            }
        } catch (const DomainSizeException &e) {
            printf("%s - skipping\n", e.what());
        } catch (const InvalidSizeException &e) {
            printf("%s - skipping\n", e.what());
        }
    }
}

template<typename FieldType>
void test_lagrange_coefficients() {
    using value_type = typename FieldType::value_type;

    const size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    for (int key = 0; key < 5; key++) {

        try {
            if (key == 0)
                domain.reset(new basic_radix2_domain<FieldType>(m));
            else if (key == 1)
                domain.reset(new extended_radix2_domain<FieldType>(m));
            else if (key == 2)
                domain.reset(new step_radix2_domain<FieldType>(m));
            else if (key == 3)
                domain.reset(new geometric_sequence_domain<FieldType>(m));
            else if (key == 4)
                domain.reset(new arithmetic_sequence_domain<FieldType>(m));

            std::vector<value_type> a;
            a = domain->evaluate_all_lagrange_polynomials(t);

            std::vector<value_type> d(m);
            for (size_t i = 0; i < m; i++) {
                d[i] = domain->get_domain_element(i);
            }

            for (size_t i = 0; i < m; i++) {
                value_type e = evaluate_lagrange_polynomial(m, d, t, i);
                printf("%ld == %ld\n", e.as_ulong(), a[i].as_ulong());
                BOOST_CHECK(e == a[i]);
            }
        } catch (const DomainSizeException &e) {
            printf("%s - skipping\n", e.what());
        } catch (const InvalidSizeException &e) {
            printf("%s - skipping\n", e.what());
        }
    }
}

template<typename FieldType>
void test_compute_z() {
    using value_type = typename FieldType::value_type;

    const size_t m = 8;
    value_type t = value_type(10);

    std::shared_ptr<evaluation_domain<FieldType>> domain;
    for (int key = 0; key < 5; key++) {
        try {
            if (key == 0)
                domain.reset(new basic_radix2_domain<FieldType>(m));
            else if (key == 1)
                domain.reset(new extended_radix2_domain<FieldType>(m));
            else if (key == 2)
                domain.reset(new step_radix2_domain<FieldType>(m));
            else if (key == 3)
                domain.reset(new geometric_sequence_domain<FieldType>(m));
            else if (key == 4)
                domain.reset(new arithmetic_sequence_domain<FieldType>(m));

            value_type a;
            a = domain->compute_vanishing_polynomial(t);

            value_type Z = value_type::one();
            for (size_t i = 0; i < m; i++) {
                Z *= (t - domain->get_domain_element(i));
            }

            BOOST_CHECK(Z == a);
        } catch (const DomainSizeException &e) {
            printf("%s - skipping\n", e.what());
        } catch (const InvalidSizeException &e) {
            printf("%s - skipping\n", e.what());
        }
    }
}

BOOST_AUTO_TEST_SUITE(fft_evaluation_domain_test_suite)

BOOST_AUTO_TEST_CASE(fft) {
    test_fft<fields::bls12<381>>();
}

BOOST_AUTO_TEST_CASE(inverse_fft_to_fft) {
    test_inverse_fft_to_fft<fields::bls12<381>>();
}
BOOST_AUTO_TEST_CASE(inverse_coset_ftt_to_coset_fft) {
    test_inverse_coset_ftt_to_coset_fft<fields::bls12<381>>();
}
BOOST_AUTO_TEST_CASE(lagrange_coefficients) {
    test_lagrange_coefficients<fields::bls12<381>>();
}
BOOST_AUTO_TEST_CASE(compute_z) {
    test_compute_z<fields::bls12<381>>();
}

BOOST_AUTO_TEST_SUITE_END()
