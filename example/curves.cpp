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
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/algebra/curves/alt_bn128.hpp>
#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>
#include <nil/crypto3/algebra/curves/jubjub.hpp>
#include <nil/crypto3/algebra/curves/babyjubjub.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

using namespace nil::crypto3::algebra;

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(FpCurveGroupElement e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename Fp2CurveGroupElement>
void print_fp2_curve_group_element(Fp2CurveGroupElement e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << ") (" << e.Y.data[0].data << " "
              << e.Y.data[1].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data << ")" << std::endl;
}

template<typename Fp3CurveGroupElement>
void print_fp3_curve_group_element(Fp3CurveGroupElement e) {
    std::cout << "(" << e.X.data[0].data << " " << e.X.data[1].data << e.X.data[2].data << ") (" << e.Y.data[0].data
              << " " << e.Y.data[1].data << e.Y.data[2].data << ") (" << e.Z.data[0].data << " " << e.Z.data[1].data
              << e.Z.data[2].data << ")" << std::endl;
}

// print dunctions can be made using arity in fields

template<typename FpCurveGroup>
void fp_curve_group_basic_math_examples() {
    typedef typename FpCurveGroup::value_type group_value_type;
    typedef typename FpCurveGroup::underlying_field_type::value_type field_value_type;

    field_value_type e1 = field_value_type(2), e2(3), e3(5), e4(3), e5(5), e6(7);
    group_value_type c1(e1, e2, e3), c2(e4, e5, e6);

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

    group_value_type cd = c1.doubled();

    // group_value_type cn = c1.normalize();

    // std::cout << "c1 normalized value: ";
    // print_fp_curve_group_element(cn);
}

template<typename Fp2CurveGroup>
void fp2_curve_group_basic_math_examples() {
    using group_value_type = typename Fp2CurveGroup::value_type;
    using field_value_type = typename Fp2CurveGroup::underlying_field_type::value_type;

    group_value_type c1 = group_value_type::one(), c2 = group_value_type::one().doubled();

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

    group_value_type cd = c1.doubled();

    // group_value_type cn = c1.normalize();

    // std::cout << "c1 normalized value: ";
    // print_fp2_curve_group_element(cn);
}

template<typename Fp3CurveGroup>
void fp3_curve_group_basic_math_examples() {
    using group_value_type = typename Fp3CurveGroup::value_type;
    using field_value_type = typename Fp3CurveGroup::underlying_field_type::value_type;

    group_value_type c1 = group_value_type::one(), c2 = group_value_type::one().doubled();

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

    group_value_type cd = c1.doubled();

    // group_value_type cn = c1.normalize();

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

    std::cout << "Edwards curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::edwards<183>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "Edwards curve g2 group basic math:" << std::endl;
    fp3_curve_group_basic_math_examples<curves::edwards<183>::g2_type>();

    std::cout << "----------------------------" << std::endl;

    std::cout << "BabyJubJub curve g1 group basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::babyjubjub::g1_type>();

    using babyjubjub_g1_type = typename curves::babyjubjub::g1_type;
    using bjj_g1_f_v = typename babyjubjub_g1_type::underlying_field_type::value_type;

    typename babyjubjub_g1_type::value_type 
                        P1(bjj_g1_f_v(0x274DBCE8D15179969BC0D49FA725BDDF9DE555E0BA6A693C6ADB52FC9EE7A82C_cppui254),
                           bjj_g1_f_v(0x5CE98C61B05F47FE2EAE9A542BD99F6B2E78246231640B54595FEBFD51EB853_cppui251)), 
                        P2(bjj_g1_f_v(0x2491ABA8D3A191A76E35BC47BD9AFE6CC88FEE14D607CBE779F2349047D5C157_cppui254),
                           bjj_g1_f_v(0x2E07297F8D3C3D7818DBDDFD24C35583F9A9D4ED0CB0C1D1348DD8F7F99152D7_cppui254)),
                        P3(bjj_g1_f_v(0x11805510440A3488B3B811EAACD0EC7C72DDED51978190E19067A2AFAEBAF361_cppui253),
                           bjj_g1_f_v(0x1F07AA1B3C598E2FF9FF77744A39298A0A89A9027777AF9FA100DD448E072C13_cppui253));

    typename babyjubjub_g1_type::value_type P1pP2 = P1 + P2;
    std::cout << "BabyJubJub addition test: " << std::endl;
    print_fp_curve_group_element(P1pP2);
    print_fp_curve_group_element(P3);
    assert(P1pP2 == P3);

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
