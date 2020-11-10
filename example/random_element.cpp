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

#include <iostream>

#include <boost/multiprecision/cpp_modular.hpp>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/algebra/fields/fp2.hpp>
#include <nil/crypto3/algebra/fields/fp3.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/alt_bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/bn128/base_field.hpp>
#include <nil/crypto3/algebra/fields/bn128/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/edwards/base_field.hpp>
#include <nil/crypto3/algebra/fields/edwards/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
//#include <nil/crypto3/algebra/fields/ed25519_fe.hpp>
//#include <nil/crypto3/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/crypto3/algebra/fields/modp_ietf.hpp>
//#include <nil/crypto3/algebra/fields/modp_srp.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp<FieldParams> e) {
    std::cout << e.data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp2<FieldParams> e) {
    std::cout << e.data[0].data << " " << e.data[1].data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp3<FieldParams> e) {
    std::cout << e.data[0].data << " " << e.data[1].data << " " << e.data[2].data << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp4<FieldParams> e) {
    std::cout << "fp4: \n" << print_field_element(e.data[0]) << " " << print_field_element(e.data[1]) << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp6_2over3<FieldParams> e) {
    std::cout << "fp6_2over3: \n" << print_field_element(e.data[0]) << " " << 
                                     print_field_element(e.data[1]) << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp6_3over2<FieldParams> e) {
    std::cout << "fp6_3over2: \n" << print_field_element(e.data[0]) << " " << 
                                     print_field_element(e.data[1]) << " " << 
                                     print_field_element(e.data[2]) << std::endl;
}

template<typename FieldParams>
void print_field_element(typename fields::detail::element_fp12_2over3over2<FieldParams> e) {
    std::cout << "fp12_2over3over2: \n" << print_field_element(e.data[0]) << " " << 
                                           print_field_element(e.data[1]) << std::endl;
}
template<typename FieldType>
void random_element_example(){
    typename FieldType::value_type v = random_element<FieldType>();

    std::cout << "Gotten random value:" << std::endl;
    print_field_element(v);
}

int main() {
    std::cout << "ALT_BN128-254 Fq basic math:" << std::endl;
    random_element_example<fields::alt_bn128_fq<254>>();

    /*std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::alt_bn128_fq<254>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "ALT_BN128-254 Fr basic math:" << std::endl;
    random_element_example<fields::alt_bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fq basic math:" << std::endl;
    random_element_example<fields::bls12_fq<381>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bls12_fq<381>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-381 Fr basic math:" << std::endl;
    random_element_example<fields::bls12_fr<381>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fq basic math:" << std::endl;
    random_element_example<fields::bls12_fq<377>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bls12_fq<377>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BLS12-377 Fr basic math:" << std::endl;
    random_element_example<fields::bls12_fr<377>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fq basic math:" << std::endl;
    random_element_example<fields::bn128_fq<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::bn128_fq<254>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BN128-254 Fr basic math:" << std::endl;
    random_element_example<fields::bn128_fr<254>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards Fq basic math:" << std::endl;
    random_element_example<fields::edwards_fq<183>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards Fq3 basic math:" << std::endl;
    fields_fp3_basic_math_examples<fields::fp3<fields::edwards_fq<183>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards Fr basic math:" << std::endl;
    random_element_example<fields::edwards_fr<183>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fq basic math:" << std::endl;
    random_element_example<fields::mnt4_fq<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fq2 basic math:" << std::endl;
    fields_fp2_basic_math_examples<fields::fp2<fields::mnt4_fq<298>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT4 Fr basic math:" << std::endl;
    random_element_example<fields::mnt4_fr<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fq basic math:" << std::endl;
    random_element_example<fields::mnt6_fq<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fq3 basic math:" << std::endl;
    fields_fp3_basic_math_examples<fields::fp3<fields::mnt6_fq<298>>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "MNT6 Fr basic math:" << std::endl;
    random_element_example<fields::mnt6_fr<298>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "DSA Botan 2048 basic math:" << std::endl;
    random_element_example<fields::dsa_botan<2048>>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "DSA JCE 1024 basic math:" << std::endl;
    random_element_example<fields::dsa_jce<1024>>();*/

    /*    std::cout << "----------------------------" << std::endl;

        std::cout << "FFDHE IETF 2048 basic math:" << std::endl;
        random_element_example<fields::ffdhe_ietf<2048>>();

        std::cout << "----------------------------" << std::endl;

        std::cout << "MODP IETF 1024 basic math:" << std::endl;
        random_element_example<fields::modp_ietf<1024>>();

        std::cout << "----------------------------" << std::endl;

        std::cout << "MODP SRP 1024 basic math:" << std::endl;
        random_element_example<fields::modp_srp<1024>>();*/

    return 0;
}