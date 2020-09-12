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

#include <nil/algebra/fields/fp2.hpp>
#include <nil/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/algebra/fields/bls12/base_field.hpp>
//#include <nil/algebra/fields/bls12/scalar_field.hpp>
#include <nil/algebra/fields/bn128/base_field.hpp>
//#include <nil/algebra/fields/bn128/scalar_field.hpp>
//#include <nil/algebra/fields/dsa_botan.hpp>
//#include <nil/algebra/fields/dsa_jce.hpp>
//#include <nil/algebra/fields/detail/params/bn128/base_field.hpp>
//#include <nil/algebra/fields/ed25519_fe.hpp>
//#include <nil/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/algebra/fields/modp_ietf.hpp>
//#include <nil/algebra/fields/modp_srp.hpp>

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>

using namespace nil::algebra;

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp<FieldParams> e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp2<FieldParams> e) {
    std::cout << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename FpField>
void fields_fp_basic_math_examples() {
    using policy_type = FpField;
    using value_type = typename policy_type::value_type;

    std::cout << "Field module value: " << policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407), e2(44410867), e3 = value_type::one(), e4(121160274);

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: ";
    print_field_element(e1);

    std::cout << "e2 value: ";
    print_field_element(e2);

    std::cout << "e3 value: ";
    print_field_element(e3);

    value_type e1e2 = e1 * e2, e1sqr = e1.squared();

    value_type e1sqrt = e1.sqrt();

    std::cout << "e1sqrt value: ";
    print_field_element(e1sqrt);

    std::cout << "e1sqrt * e1sqrt \n";
    print_field_element(e1sqrt * e1sqrt);

    value_type e1inv = e1.inversed();

    std::cout << "e1 inversed value: ";
    print_field_element(e1inv);

    std::cout << "e1 * e1^(-1) \n";
    print_field_element(e1 * e1inv);

    std::cout << "e1 * e2 value: ";
    print_field_element(e1e2);

    std::cout << "e1 square value: ";
    print_field_element(e1sqr);

    std::cout << "e1 square square value: ";

    print_field_element(e1.squared().squared());

    std::cout << "e1 pow 4 value: ";

    print_field_element(e1.pow(4));

    std::cout << "e1 pow 11 value: ";

    print_field_element(e1.pow(11));

    std::cout << "e1 pow 44410867 value: ";

    print_field_element(e1.pow(44410867));

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: ";

    print_field_element(complex_eq);

    std::cout << "(e1 + e2) * (e3 + e4) value: ";

    print_field_element(complex_eq1);

    std::cout << "Doubled e1 value: ";

    print_field_element(e1.doubled());

    e1 += e2;

    std::cout << "e1 += e2 value: ";

    print_field_element(e1);

}

template<typename Fp2Field>
void fields_fp2_basic_math_examples() {
    using policy_type = Fp2Field;
    using value_type = typename policy_type::value_type;

    std::cout << "Field module value: " << policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407, 44410867), e2(44410867, 1), e3 = value_type::one(), e4(121160274, 7);

    value_type ee(e1);

    std::cout << "ee value: ";
    print_field_element(ee);

    std::cout << "Non residue: " << e1.non_residue.data << std::endl;

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: ";
    print_field_element(e1);

    e1 += e2;

    std::cout << "e1 value: ";
    print_field_element(e1);
    std::cout << "ee value: ";
    print_field_element(ee);

    std::cout << "e2 value: ";
    print_field_element(e2);

    std::cout << "e3 value: ";
    print_field_element(e3);

    value_type e1inv = e1.inversed();

    std::cout << "e1 inversed value: ";
    print_field_element(e1inv);

    std::cout << "e1 * e1^(-1) \n";
    print_field_element(e1 * e1inv);
    
    value_type e1e2 = e1 * e2, e1sqr = e1.squared();

    std::cout << "e1 * e2 value: ";
    print_field_element(e1e2);

    std::cout << "e1 square value: ";
    print_field_element(e1sqr);

    std::cout << "e1 square square value: ";

    print_field_element(e1.squared().squared());

    std::cout << "e1 pow 4 value: ";

    print_field_element(e1.pow(4));

    std::cout << "e1 pow 11 value: ";

    print_field_element(e1.pow(11));

    std::cout << "e1 pow 44410867 value: ";

    print_field_element(e1.pow(44410867));

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: ";

    print_field_element(complex_eq);

    std::cout << "(e1 + e2) * (e3 + e4) value: ";

    print_field_element(complex_eq1);

    std::cout << "Doubled e1 value: ";

    print_field_element(e1.doubled());

    e1 += e2;

    std::cout << "e1 += e2 value: ";

    print_field_element(e1);

    // std::cout << "e1 inversed value: " ;

    // print_field_element(e1.inversed());
}

int main() {
    std::cout << "ALT_BN128-254 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::alt_bn128_fq<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::alt_bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bn128_fq<254>>();

    std::cout << "----------------------------" << std::endl;

    /*std::cout << "BN128-254 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;*/

    std::cout << "BLS12-381 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fq<381>>();

    std::cout << "----------------------------" << std::endl;

    /*std::cout << "BLS12-381 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fr<381>>();

    std::cout << "----------------------------" << std::endl;*/

    /*std::cout << "DSA Botan 2048 basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::dsa_botan<2048>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "DSA JCE 1024 basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::dsa_jce<1024>>();*/

    /*    std::cout << "----------------------------" << std::endl;

        std::cout << "FFDHE IETF 2048 basic math:" << std::endl;
        fields_fp_basic_math_examples<fields::ffdhe_ietf<2048>>();

        std::cout << "----------------------------" << std::endl;

        std::cout << "MODP IETF 1024 basic math:" << std::endl;
        fields_fp_basic_math_examples<fields::modp_ietf<1024>>();

        std::cout << "----------------------------" << std::endl;

        std::cout << "MODP SRP 1024 basic math:" << std::endl;
        fields_fp_basic_math_examples<fields::modp_srp<1024>>();*/

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bn128_fq<254>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::alt_bn128_fq<254>>>();

    return 0;
}