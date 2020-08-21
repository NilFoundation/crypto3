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

#include <nil/algebra/fields/bls12/fq.hpp>
#include <nil/algebra/fields/bls12/fr.hpp>
#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fq2.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>
#include <nil/algebra/fields/dsa_botan.hpp>
#include <nil/algebra/fields/dsa_jce.hpp>
//#include <nil/algebra/fields/ed25519_fe.hpp>
//#include <nil/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/algebra/fields/modp_ietf.hpp>
//#include <nil/algebra/fields/modp_srp.hpp>

using namespace nil::algebra;

template <typename FpField>
void fields_fp_basic_math_examples()
{  
    using policy_type = FpField;
    using value_type = typename policy_type::value_type;

    std::cout << "Field module value: " <<  policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407), e2(44410867), e3 = value_type::one(), e4(121160274);

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " <<  e1.data << std::endl;
    std::cout << "e2 value: " <<  e2.data << std::endl;
    std::cout << "e3 value: " <<  e3.data << std::endl;

    value_type e1e3 = e1 * e3, e1sqr = e1.square();

    std::cout << "e1 * e3 value: " <<  e1e3.data << std::endl;
    std::cout << "e1 square value: " <<  e1sqr.data << std::endl;

    std::cout << "e1 square square value: " <<  e1.square().square().data << std::endl;

    std::cout << "e1 pow 4 value: " <<  e1.pow(4).data << std::endl;

    std::cout << "e1 pow 11 value: " <<  e1.pow(11).data << std::endl;

    std::cout << "e1 pow 44410867 value: " <<  e1.pow(44410867).data << std::endl;

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: " <<  complex_eq.data << std::endl;
    std::cout << "(e1 + e2) * (e3 + e4) value: " <<  complex_eq1.data << std::endl;

    std::cout << "Double e1 value: " << e1.dbl().data << std::endl;

    e1 += e2;

    std::cout << "e1 += e2 value: " << e1.data << std::endl;
}

template <typename Fp2Field>
void fields_fp2_basic_math_examples()
{  
    using policy_type = Fp2Field;
    using value_type = typename policy_type::value_type;

    std::cout << "Field module value: " <<  policy_type::modulus << std::endl;

    value_type e1 = value_type({76749407, 44410867}), e2({44410867, 1}), e3 = value_type::one(), e4({121160274, 7});

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " <<  e1.data[0].data << " " << e1.data[1].data << std::endl;
    std::cout << "e2 value: " <<  e2.data[0].data << " " << e2.data[1].data << std::endl;
    std::cout << "e3 value: " <<  e3.data[0].data << " " << e3.data[1].data << std::endl;

    value_type e1e3 = e1 * e3, e1sqr = e1.square();

    std::cout << "e1 * e3 value: " <<  e1e3.data[0].data << " " << e1e3.data[1].data << std::endl;
    std::cout << "e1 square value: " <<  e1sqr.data[0].data << " " << e1sqr.data[1].data << std::endl;
/*
    std::cout << "e1 square square value: " <<  e1.square().square().data << std::endl;

    std::cout << "e1 pow 4 value: " <<  e1.pow(4).data << std::endl;

    std::cout << "e1 pow 11 value: " <<  e1.pow(11).data << std::endl;

    std::cout << "e1 pow 44410867 value: " <<  e1.pow(44410867).data << std::endl;

    value_type complex_eq = e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4;
    value_type complex_eq1 = (e1 + e2) * (e3 + e4);

    std::cout << "e1 * e3 + e1 * e4 + e2 * e3 + e2 * e4 value: " <<  complex_eq.data << std::endl;
    std::cout << "(e1 + e2) * (e3 + e4) value: " <<  complex_eq1.data << std::endl;

    std::cout << "Double e1 value: " << e1.dbl().data << std::endl;

    e1 += e2;

    std::cout << "e1 += e2 value: " << e1.data << std::endl;*/
}

int main()
{
    std::cout << "BN128-254 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bn128_fq<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fq basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fq<381>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fr basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::bls12_fr<255>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "DSA Botan 2048 basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::dsa_botan<2048>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "DSA JCE 1024 basic math:" << std::endl;
    fields_fp_basic_math_examples<fields::dsa_jce<1024>>();

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
    fields_fp2_basic_math_examples<fields::bn128_fq2<254>>();

    return 0;
}