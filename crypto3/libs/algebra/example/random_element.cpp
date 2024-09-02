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

#include <iostream>

#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#include <boost/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

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

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp4.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_2over3.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>

#include <nil/crypto3/algebra/random_element.hpp>

using namespace nil::crypto3::algebra;


template<typename FieldType>
void random_field_element_example(){
    typename FieldType::value_type v = random_element<FieldType>();

    std::cout << "Got random value:" << v << std::endl;
}

template<typename CurveGroupType>
void random_group_element_example(){
    typename CurveGroupType::value_type v = random_element<CurveGroupType>();

    std::cout << "Got random value:" << v << std::endl;
}

int main() {
    std::cout << "ALT_BN128-254 Fq random element choice:" << std::endl;
    random_field_element_example<typename fields::alt_bn128_fq<254>>();

    std::cout << "BLS12-381 Gt random element choice:" << std::endl;
    random_field_element_example<typename curves::bls12<381>::gt_type>();

    std::cout << "BLS12-381 G1 random element choice:" << std::endl;
    random_group_element_example<typename curves::bls12<381>::g1_type>();

    return 0;
}
