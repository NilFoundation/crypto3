//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE curves_algebra_test

#include <iostream>

#include <boost/multiprecision/cpp_modular.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>
#include <nil/algebra/fields/dsa_botan.hpp>

#include <nil/algebra/fields/bls12/fq.hpp>
#include <nil/algebra/fields/bls12/fr.hpp>
//#include <nil/algebra/fields/detail/params/dsa_jce.hpp>
//#include <nil/algebra/fields/detail/params/modp_srp.hpp>
//#include <nil/algebra/fields/detail/params/params.hpp>
//#include <nil/algebra/fields/bn128/fr.hpp>
//#include <nil/algebra/fields/dsa_jce.hpp>
//#include <nil/algebra/fields/ed25519_fe.hpp>
//#include <nil/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/algebra/fields/fp.hpp>
//#include <nil/algebra/fields/fp2.hpp>
//#include <nil/algebra/fields/fp3.hpp>
//#include <nil/algebra/fields/fp4.hpp>
//#include <nil/algebra/fields/fp6_2over3.hpp>
//#include <nil/algebra/fields/fp6_3over2.hpp>
//#include <nil/algebra/fields/fp12_2over3over2.hpp>
//#include <nil/algebra/fields/modp_ietf.hpp>
//#include <nil/algebra/fields/modp_srp.hpp>

using namespace nil::algebra;

BOOST_AUTO_TEST_SUITE(curves_manual_tests)

BOOST_AUTO_TEST_CASE(curves_manual_test1) {
    
    using value_type = fields::dsa_botan<2048, 2048>::value_type;

    const fields::dsa_botan<2048, 2048>::modulus_type m = fields::dsa_botan<2048, 2048>::modulus;

    value_type e1 = value_type::one(), e2(3);

    std::cout << e1.is_one() << e2.is_one() << e2.is_zero() << std::endl;

    value_type e3 = e1.dbl() * e2.square();

    value_type e4 = e1 * e2 * e2 + e1 * e2 * e2;

    std::cout << "4 == e1 + e2 ? : " << (value_type(4) == e1 + e2) << std::endl;

    std::cout << "4 == e3 ? : " << (value_type(4) == e3) << std::endl;

    std::cout << "E2 value: " << e2.data << std::endl;

    std::cout << "Modulus value: " << m << std::endl;

    std::cout << (e4 == e3);

    //assert(e4 == e3);
    BOOST_CHECK_EQUAL(e4.data, e3.data);
}
BOOST_AUTO_TEST_SUITE_END()
/*
BOOST_AUTO_TEST_SUITE(fields_dsa_botan_tests)
BOOST_AUTO_TEST_CASE(fields_dsa_botan_test1) {
    
    using value_type = fields::dsa_botan<2048, 2048>::value_type;

    const fields::dsa_botan<2048, 2048>::modulus_type m = fields::dsa_botan<2048, 2048>::modulus;

    value_type e1 = value_type::one(), e2(3);

    std::cout << e1.is_one() << e2.is_one() << e2.is_zero() << std::endl;

    value_type e3 = e1.dbl() * e2.square();

    value_type e4 = e1 * e2 * e2 + e1 * e2 * e2;

    std::cout << "4 == e1 + e2 ? : " << (value_type(4) == e1 + e2) << std::endl;

    std::cout << "4 == e3 ? : " << (value_type(4) == e3) << std::endl;

    std::cout << "E2 value: " << e2.data << std::endl;

    std::cout << "Modulus value: " << m << std::endl;

    std::cout << (e4 == e3);

    //assert(value_type(4) == e3);
    BOOST_CHECK_EQUAL(value_type(4).data, e3.data);
}
BOOST_AUTO_TEST_SUITE_END()*/


/*
template<typename FieldType, typename NumberType>
void test_field() {
    NumberType rand1  = NumberType ("76749407");
    NumberType rand2 = NumberType ("44410867");
    NumberType randsum = NumberType ("121160274");

    FieldType zero = FieldType::zero();
    FieldType one = FieldType::one();
    FieldType a = FieldType::random_element();
    FieldType a_ser;
    a_ser = reserialize<FieldType>(a);
    assert(a_ser == a);

    FieldType b = FieldType::random_element();
    FieldType c = FieldType::random_element();
    FieldType d = FieldType::random_element();

    assert(a != zero);
    assert(a != one);

    assert(a * a == a.squared());
    assert((a + b).squared() == a.squared() + a * b + b * a + b.squared());
    assert((a + b) * (c + d) == a * c + a * d + b * c + b * d);
    assert(a - b == a + (-b));
    assert(a - b == (-b) + a);

    assert((a ^ rand1) * (a ^ rand2) == (a ^ randsum));

    assert(a * a.inverse() == one);
    assert((a + b) * c.inverse() == a * c.inverse() + (b.inverse() * c).inverse());
}

template<typename FieldType>
void test_sqrt() {
    for (std::size_t i = 0; i < 100; ++i) {
        FieldType a = FieldType::random_element();
        FieldType asq = a.squared();
        assert(asq.sqrt() == a || asq.sqrt() == -a);
    }
}

template<typename FieldType>
void test_two_squarings() {
    FieldType a = FieldType::random_element();
    assert(a.squared() == a * a);
    assert(a.squared() == a.squared_complex());
    assert(a.squared() == a.squared_karatsuba());
}

template<typename FieldType>
void test_Frobenius() {
    FieldType a = FieldType::random_element();
    assert(a.Frobenius_map(0) == a);
    FieldType a_q = a ^ FieldType::base_field_char();
    for (std::size_t power = 1; power < 10; ++power) {
        const FieldType a_qi = a.Frobenius_map(power);
        assert(a_qi == a_q);

        a_q = a_q ^ FieldType::base_field_char();
    }
}

template<typename FieldType>
void test_unitary_inverse() {
    assert(FieldType::extension_degree() % 2 == 0);
    FieldType a = FieldType::random_element();
    FieldType aqcubed_minus1 = a.Frobenius_map(FieldType::extension_degree() / 2) * a.inverse();
    assert(aqcubed_minus1.inverse() == aqcubed_minus1.unitary_inverse());
}

template<typename FieldType>
void test_cyclotomic_squaring();

template<>
void test_cyclotomic_squaring<Fqk<edwards_pp>>() {
    typedef Fqk<edwards_pp> FieldType;
    assert(FieldType::extension_degree() % 2 == 0);
    FieldType a = FieldType::random_element();
    FieldType a_unitary = a.Frobenius_map(FieldType::extension_degree() / 2) * a.inverse();
    // beta = a^((q^(k/2)-1)*(q+1))
    FieldType beta = a_unitary.Frobenius_map(1) * a_unitary;
    assert(beta.cyclotomic_squared() == beta.squared());
}

template<>
void test_cyclotomic_squaring<Fqk<mnt4_pp>>() {
    typedef Fqk<mnt4_pp> FieldType;
    assert(FieldType::extension_degree() % 2 == 0);
    FieldType a = FieldType::random_element();
    FieldType a_unitary = a.Frobenius_map(FieldType::extension_degree() / 2) * a.inverse();
    // beta = a^(q^(k/2)-1)
    FieldType beta = a_unitary;
    assert(beta.cyclotomic_squared() == beta.squared());
}

template<>
void test_cyclotomic_squaring<Fqk<mnt6_pp>>() {
    typedef Fqk<mnt6_pp> FieldType;
    assert(FieldType::extension_degree() % 2 == 0);
    FieldType a = FieldType::random_element();
    FieldType a_unitary = a.Frobenius_map(FieldType::extension_degree() / 2) * a.inverse();
    // beta = a^((q^(k/2)-1)*(q+1))
    FieldType beta = a_unitary.Frobenius_map(1) * a_unitary;
    assert(beta.cyclotomic_squared() == beta.squared());
}

template<typename CurveType>
void test_all_fields() {
    test_field<Fr<CurveType>>();
    test_field<Fq<CurveType>>();
    test_field<Fqe<CurveType>>();
    test_field<Fqk<CurveType>>();

    test_sqrt<Fr<CurveType>>();
    test_sqrt<Fq<CurveType>>();
    test_sqrt<Fqe<CurveType>>();

    test_Frobenius<Fqe<CurveType>>();
    test_Frobenius<Fqk<CurveType>>();

    test_unitary_inverse<Fqk<CurveType>>();
}

template<typename Fp4T>
void test_Fp4_tom_cook() {
    typedef typename Fp4T::my_Fp FieldType;
    for (size_t i = 0; i < 100; ++i) {
        const Fp4T a = Fp4T::random_element();
        const Fp4T b = Fp4T::random_element();
        const Fp4T correct_res = a * b;

        Fp4T res;

        const FieldType &a0 = a.c0.c0, &a1 = a.c1.c0, &a2 = a.c0.c1, &a3 = a.c1.c1;

        const FieldType &b0 = b.c0.c0, &b1 = b.c1.c0, &b2 = b.c0.c1, &b3 = b.c1.c1;

        FieldType &c0 = res.c0.c0, &c1 = res.c1.c0, &c2 = res.c0.c1, &c3 = res.c1.c1;

        const FieldType v0 = a0 * b0;
        const FieldType v1 = (a0 + a1 + a2 + a3) * (b0 + b1 + b2 + b3);
        const FieldType v2 = (a0 - a1 + a2 - a3) * (b0 - b1 + b2 - b3);
        const FieldType v3 = (a0 + FieldType(2) * a1 + FieldType(4) * a2 + FieldType(8) * a3) *
                          (b0 + FieldType(2) * b1 + FieldType(4) * b2 + FieldType(8) * b3);
        const FieldType v4 = (a0 - FieldType(2) * a1 + FieldType(4) * a2 - FieldType(8) * a3) *
                          (b0 - FieldType(2) * b1 + FieldType(4) * b2 - FieldType(8) * b3);
        const FieldType v5 = (a0 + FieldType(3) * a1 + FieldType(9) * a2 + FieldType(27) * a3) *
                          (b0 + FieldType(3) * b1 + FieldType(9) * b2 + FieldType(27) * b3);
        const FieldType v6 = a3 * b3;

        const FieldType beta = Fp4T::non_residue;

        c0 = v0 + beta * (FieldType(4).inverse() * v0 - FieldType(6).inverse() * (v1 + v2) +
                          FieldType(24).inverse() * (v3 + v4) - FieldType(5) * v6);
        c1 = -FieldType(3).inverse() * v0 + v1 - FieldType(2).inverse() * v2 - FieldType(4).inverse() * v3 +
             FieldType(20).inverse() * v4 + FieldType(30).inverse() * v5 - FieldType(12) * v6 +
             beta * (-FieldType(12).inverse() * (v0 - v1) + FieldType(24).inverse() * (v2 - v3) -
                     FieldType(120).inverse() * (v4 - v5) - FieldType(3) * v6);
        c2 = -(FieldType(5) * (FieldType(4).inverse())) * v0 + (FieldType(2) * (FieldType(3).inverse())) * (v1 + v2) -
             FieldType(24).inverse() * (v3 + v4) + FieldType(4) * v6 + beta * v6;
        c3 = FieldType(12).inverse() * (FieldType(5) * v0 - FieldType(7) * v1) -
             FieldType(24).inverse() * (v2 - FieldType(7) * v3 + v4 + v5) + FieldType(15) * v6;

        assert(res == correct_res);

        // {v0, v3, v4, v5}
        const FieldType u = (FieldType::one() - beta).inverse();
        assert(v0 == u * c0 + beta * u * c2 - beta * u * FieldType(2).inverse() * v1 -
                         beta * u * FieldType(2).inverse() * v2 + beta * v6);
        assert(v3 == -FieldType(15) * u * c0 - FieldType(30) * u * c1 - FieldType(3) * (FieldType(4) + beta) * u * c2 -
                         FieldType(6) * (FieldType(4) + beta) * u * c3 +
                         (FieldType(24) - FieldType(3) * beta * FieldType(2).inverse()) * u * v1 +
                         (-FieldType(8) + beta * FieldType(2).inverse()) * u * v2 - FieldType(3) * (-FieldType(16) + beta) * v6);
        assert(v4 == -FieldType(15) * u * c0 + FieldType(30) * u * c1 - FieldType(3) * (FieldType(4) + beta) * u * c2 +
                         FieldType(6) * (FieldType(4) + beta) * u * c3 +
                         (FieldType(24) - FieldType(3) * beta * FieldType(2).inverse()) * u * v2 +
                         (-FieldType(8) + beta * FieldType(2).inverse()) * u * v1 - FieldType(3) * (-FieldType(16) + beta) * v6);
        assert(v5 == -FieldType(80) * u * c0 - FieldType(240) * u * c1 - FieldType(8) * (FieldType(9) + beta) * u * c2 -
                         FieldType(24) * (FieldType(9) + beta) * u * c3 - FieldType(2) * (-FieldType(81) + beta) * u * v1 +
                         (-FieldType(81) + beta) * u * v2 - FieldType(8) * (-FieldType(81) + beta) * v6);

        // c0 + beta c2 - (beta v1)/2 - (beta v2)/ 2 - (-1 + beta) beta v6,
        // -15 c0 - 30 c1 - 3 (4 + beta) c2 - 6 (4 + beta) c3 + (24 - (3 beta)/2) v1 + (-8 + beta/2) v2 + 3 (-16 + beta)
        // (-1 + beta) v6, -15 c0 + 30 c1 - 3 (4 + beta) c2 + 6 (4 + beta) c3 + (-8 + beta/2) v1 + (24 - (3 beta)/2) v2
        // + 3 (-16 + beta) (-1 + beta) v6, -80 c0 - 240 c1 - 8 (9 + beta) c2 - 24 (9 + beta) c3 - 2 (-81 + beta) v1 +
        // (-81 + beta) v2 + 8 (-81 + beta) (-1 + beta) v6
    }
}

int main(void) {
    edwards_pp::init_public_params();
    test_all_fields<edwards_pp>();
    test_cyclotomic_squaring<Fqk<edwards_pp>>();

    mnt4_pp::init_public_params();
    test_all_fields<mnt4_pp>();
    test_Fp4_tom_cook<mnt4_Fq4>();
    test_two_squarings<Fqe<mnt4_pp>>();
    test_cyclotomic_squaring<Fqk<mnt4_pp>>();

    mnt6_pp::init_public_params();
    test_all_fields<mnt6_pp>();
    test_cyclotomic_squaring<Fqk<mnt6_pp>>();

    alt_bn128_pp::init_public_params();
    test_field<alt_bn128_Fq6>();
    test_Frobenius<alt_bn128_Fq6>();
    test_all_fields<alt_bn128_pp>();

    bn128_pp::init_public_params();
    test_field<Fr<bn128_pp>>();
    test_field<Fq<bn128_pp>>();
}
*/