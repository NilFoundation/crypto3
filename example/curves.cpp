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
#include <nil/algebra/fields/bn128/fq2.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>

using namespace nil::algebra;

template <typename FieldValueType>
void print_curve_element (typename curves::detail::element_curve_weierstrass<FieldValueType> e){
    std::cout << e.p[0].data << " " << e.p[1].data << " " << e.p[2].data << std::endl;
}

template <typename CurveWeierstrass>
void curve_weierstrass_basic_math_examples()
{  
    using policy_type = CurveWeierstrass;
    using value_type = typename policy_type::value_type;
    using field_value_type = typename policy_type::base_field_type::value_type;

    std::cout << "Field module value: " <<  policy_type::base_field_type::modulus << std::endl;

    field_value_type e1 = field_value_type(76749407), e2(44410867), e3 = field_value_type::one(), e4(121160274), e5(5), e6 = field_value_type::zero();
    value_type c1(e1, e2, e3), c2(e4, e5, e6);

    std::cout << "Curve element values: " << std::endl;
    std::cout << "c1 value: ";
    print_curve_element(c1);

    std::cout << "c2 value: ";
    print_curve_element(c2);

    std::cout << "c1 + c2 value: ";
    print_curve_element(c1 + c2);


}

int main()
{
    std::cout << "BN128-254 curve basic math:" << std::endl;
    curve_weierstrass_basic_math_examples<curves::bn128<254>>();

    std::cout << "----------------------------" << std::endl;

    return 0;
}