//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <iostream>

#include <boost/multiprecision/cpp_modular.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/bn128.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

using namespace nil::crypto3::algebra;

template<typename FpCurveGroup>
void print_fp_curve_group_element(FpCurveGroup e) {
    std::cout << e.p[0].data << " " << e.p[1].data << " " << e.p[2].data << std::endl;
}

template<typename Fp2CurveGroup>
void print_fp2_curve_group_element(Fp2CurveGroup e) {
    std::cout << "(" << e.p[0].data[0].data << " " << e.p[0].data[1].data << ") (" << e.p[1].data[0].data << " "
              << e.p[1].data[1].data << ") (" << e.p[2].data[0].data << " " << e.p[2].data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroup>
void print_fp3_curve_group_element(Fp3CurveGroup e) {
    std::cout << "(" << e.p[0].data[0].data << " " << e.p[0].data[1].data << e.p[0].data[2].data << ") ("
              << e.p[1].data[0].data << " " << e.p[1].data[1].data << e.p[1].data[2].data << ") ("
              << e.p[2].data[0].data << " " << e.p[2].data[1].data << e.p[2].data[2].data << ")" << std::endl;
}

// print dunctions can be made using arity in fields

template<typename FpCurveGroup>
void fp_curve_group_basic_math_examples() {
    using policy_type = FpCurveGroup;
    using field_value_type = typename policy_type::underlying_field_type_value;

    field_value_type e1 = field_value_type(2), e2(3), e3(5), e4(3), e5(5), e6(7);
    policy_type c1(e1, e2, e3), c2(e4, e5, e6);

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_fp_curve_group_element(c1);

    std::cout << "c2 value: ";
    print_fp_curve_group_element(c2);

    std::cout << "c1 + c2 value: ";
    print_fp_curve_group_element(c1 + c2);

    std::cout << "c1 - c2 value: ";
    print_fp_curve_group_element(c1 - c2);

    std::cout << "Doubled c1 value: ";
    print_fp_curve_group_element(c1.doubled());

    policy_type cd = c1.doubled();

    // policy_type cn = c1.normalize();

    // std::cout << "c1 normalized value: ";
    // print_fp_curve_group_element(cn);
}

template<typename Fp2CurveGroup>
void fp2_curve_group_basic_math_examples() {
    using policy_type = Fp2CurveGroup;
    using field_value_type = typename policy_type::underlying_field_type_value;

    policy_type c1 = policy_type::one(), c2 = policy_type::one().doubled();

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_fp2_curve_group_element(c1);

    std::cout << "c2 value: ";
    print_fp2_curve_group_element(c2);

    std::cout << "c1 + c2 value: ";
    print_fp2_curve_group_element(c1 + c2);

    std::cout << "c1 - c2 value: ";
    print_fp2_curve_group_element(c1 - c2);

    std::cout << "Doubled c1 value: ";
    print_fp2_curve_group_element(c1.doubled());

    policy_type cd = c1.doubled();

    // policy_type cn = c1.normalize();

    // std::cout << "c1 normalized value: ";
    // print_fp2_curve_group_element(cn);
}

template<typename Fp3CurveGroup>
void fp3_curve_group_basic_math_examples() {
    using policy_type = Fp3CurveGroup;
    using field_value_type = typename policy_type::underlying_field_type_value;

    policy_type c1 = policy_type::one(), c2 = policy_type::one().doubled();

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_fp3_curve_group_element(c1);

    std::cout << "c2 value: ";
    print_fp3_curve_group_element(c2);

    std::cout << "c1 + c2 value: ";
    print_fp3_curve_group_element(c1 + c2);

    std::cout << "c1 - c2 value: ";
    print_fp3_curve_group_element(c1 - c2);

    std::cout << "Doubled c1 value: ";
    print_fp3_curve_group_element(c1.doubled());

    policy_type cd = c1.doubled();

    // policy_type cn = c1.normalize();

    // std::cout << "c1 normalized value: ";
    // print_fp3_curve_group_element(cn);
}

int main() {
    std::cout << "ALT_BN128-254 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::alt_bn128<254>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 curve g2 group basic math:" << std::endl;
    fp2_curve_group_basic_math_examples<curves::alt_bn128<254>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::bls12<381>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 curve g2 group basic math:" << std::endl;
    fp2_curve_group_basic_math_examples<curves::bls12<381>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::bls12<377>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 curve g2 group basic math:" << std::endl;
    fp2_curve_group_basic_math_examples<curves::bls12<377>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::bn128<254>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 curve g2 group basic math:" << std::endl;
    fp2_curve_group_basic_math_examples<curves::bn128<254>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::edwards<183>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards curve g2 group basic math:" << std::endl;
    fp3_curve_group_basic_math_examples<curves::edwards<183>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Mnt4 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::mnt4<298>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Mnt4 curve g2 group basic math:" << std::endl;
    fp2_curve_group_basic_math_examples<curves::mnt4<298>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Mnt6 curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::mnt6<298>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Mnt6 curve g2 group basic math:" << std::endl;
    fp3_curve_group_basic_math_examples<curves::mnt6<298>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    return 0;
}