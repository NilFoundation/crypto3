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

#include <nil/crypto3/multiprecision/cpp_modular.hpp>
#include <nil/crypto3/multiprecision/number.hpp>
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>

#include <nil/crypto3/algebra/curves/secp_r1.hpp>

using namespace nil::crypto3::algebra;

template<typename FpCurveGroupElement>
void print_fp_curve_group_element(FpCurveGroupElement e) {
    std::cout << e.X.data << " " << e.Y.data << " " << e.Z.data << std::endl;
}

template<typename FpCurveGroup>
void coordinates_examples() {
    typedef typename FpCurveGroup::value_type group_value_type;
    typedef typename FpCurveGroup::field_type::value_type field_value_type;

    field_value_type e1 = field_value_type(0xfadaf4efc388b9fb1f5f6286032868c8c29a4d7b359f17bff792511cdbcea8ba_cppui256),
    e2(0x609eaeb55609889d764de70df4536a52a6773ce14244d2109afb1f6140d64ed2_cppui256), e3(1),
    e4(0x72213568b6cec6bad10c649c22d9388857085132ea254320c7d3c12727f55d97_cppui256),
    e5(0xff9d5ca60a4f5ae00b2abdb6dddb3f4fc5c853ed56a33a85ccaa7d3093084579_cppui256), e6(1);
  

	
    group_value_type c1(e1, e2, e3), c2(e4, e5, e6);//, c3(e7,e8,e9),c4(e10,e11,e12);

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_fp_curve_group_element(c1);
    std::cout << "c2 value: ";
    print_fp_curve_group_element(c2);
    std::cout << "c1 + c2 value: ";
    print_fp_curve_group_element(c1 + c2);
    std::cout << "c1 - c2 value: ";
    print_fp_curve_group_element(c1-c2);
    std::cout << "Doubled c1 value: ";
    print_fp_curve_group_element(c1.doubled());
  }

int main() {
    std::cout << "Secp256r1 Jacobian coordinates with a4=-3" << std::endl;

    coordinates_examples<curves::secp_r1<256>::g1_type< curves::coordinates::jacobian_with_a4_minus_3,  curves::forms::short_weierstrass>>();//<coordinates::jacobian_with_a4_minus_3>>()//()_g1_params<160, forms::short_weierstrass>

    std::cout << "----------------------------" << std::endl;

    std::cout << "Secp256r1 Jacobian coordinates" << std::endl;

    coordinates_examples<curves::secp_r1<256>::g1_type< curves::coordinates::jacobian,  curves::forms::short_weierstrass>>();//<coordinates::jacobian_with_a4_minus_3>>()//()_g1_params<160, forms::short_weierstrass>

    std::cout << "----------------------------" << std::endl;
    return 0;
}
