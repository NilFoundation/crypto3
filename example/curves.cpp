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


#include <nil/algebra/curves/bn128.hpp>

#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>

using namespace nil::algebra;

template <typename FpCurveGroup>
void print_fp_curve_group_element (FpCurveGroup e){
    std::cout << e.p[0].data << " " << e.p[1].data << " " << e.p[2].data << std::endl;
}

template <typename Fp2CurveGroup>
void print_fp2_curve_group_element (Fp2CurveGroup e){
    std::cout << "(" << e.p[0].data[0].data << " " << e.p[0].data[1].data << ") (" <<  e.p[1].data[0].data << " " << e.p[1].data[1].data << ") (" << e.p[2].data[0].data << " " << e.p[2].data[1].data << ")" << std::endl;
}

template <typename FpCurveGroup>
void fp_curve_group_basic_math_examples()
{  
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

    std::cout << "Double c1 value: ";
    print_fp_curve_group_element(c1.doubled());

    policy_type cd = c1.doubled();
    
    policy_type cn = c1.normalize();
    
    std::cout << "c1 normalized value: ";
    print_fp_curve_group_element(cn);

}

int main()
{
    std::cout << "BN128-254 curve basic math:" << std::endl;
    fp_curve_group_basic_math_examples<curves::bn128<254>::g1_type>();

    std::cout << "----------------------------" << std::endl;

    return 0;
}