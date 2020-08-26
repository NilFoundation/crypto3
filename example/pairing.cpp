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
#include <nil/algebra/curves/detail/params/bn128.hpp>

#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fq2.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>

#include <nil/algebra/curves/detail/bn128/g1.hpp>

using namespace nil::algebra;

template <typename FieldValueType>
void print_curve_element (typename curves::detail::element_curve_weierstrass<FieldValueType> e){
    std::cout << e.p[0].data << " " << e.p[1].data << " " << e.p[2].data << std::endl;
}

template <typename CurveWeierstrass>
void curve_weierstrass_pairing_math_examples()
{  
    using value_type = typename curves::bn128<254>::g1_type;
    using field_value_type = typename value_type::underlying_field_type;

    //std::cout << "Field module value: " <<  policy_type::base_field_type::modulus << std::endl;

    field_value_type e1 = field_value_type(2), e2(3), e3(5), e4(3), e5(5), e6(7);
    value_type c1(e1, e2, e3), c2(e4, e5, e6), c3(c1);

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_curve_element(c1);

    std::cout << "c2 value: ";
    print_curve_element(c2);

    std::cout << "c1 + c2 value: ";
    print_curve_element(c1 + c2);

    std::cout << "c1 - c2 value: ";
    print_curve_element(c1 - c2);

    std::cout << "Double c1 value: ";
    print_curve_element(c1.dbl());
    
    std::cout << "c1 == c2 value: ";
    std::cout << (c1 == c2) << std::endl;

    std::cout << "c1 == c3 value: ";
    std::cout << (c1 == c3) << std::endl;

    c1 = c2;

    std::cout << "c1 == c3 after c1 = c2 value: ";
    std::cout << (c1 == c3) << std::endl;

    /*value_type cn = c1.normalize();
    
    std::cout << "c1 normalized value: ";
    print_curve_element(cn);*/

}

int main()
{
    std::cout << "BN128-254 curve pairing math:" << std::endl;
    curve_weierstrass_pairing_math_examples<curves::bn128<254>>();

    std::cout << "----------------------------" << std::endl;

    return 0;
}