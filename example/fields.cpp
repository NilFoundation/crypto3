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

#include <nil/algebra/fields/bn128/fq.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>
#include <nil/algebra/fields/dsa_botan.hpp>

#include <nil/algebra/fields/bls12/fq.hpp>
#include <nil/algebra/fields/bls12/fr.hpp>
//#include <nil/algebra/fields/detail/params/dsa_jce.hpp>
//#include <nil/algebra/fields/detail/params/modp_srp.hpp>
//#include <nil/algebra/fields/detail/params/params.hpp>
//#include <nil/algebra/fields/bn128/fr.hpp>
//#include <nil/algebra/fields/dsa_jce.hpp>
//#include <nil/algebra/fields/ed25519_fe.hpp>
//#include <nil/algebra/fields/ffdhe_ietf.hpp>
//#include <nil/algebra/fields/fp.hpp>
//#include <nil/algebra/fields/fp2.hpp>
//#include <nil/algebra/fields/fp3.hpp>
//#include <nil/algebra/fields/fp4.hpp>
//#include <nil/algebra/fields/fp6_2over3.hpp>
//#include <nil/algebra/fields/fp6_3over2.hpp>
//#include <nil/algebra/fields/fp12_2over3over2.hpp>
//#include <nil/algebra/fields/modp_ietf.hpp>
//#include <nil/algebra/fields/modp_srp.hpp>

using namespace nil::algebra;

void bn128_fq_number_examples()
{  
    using policy_type = fields::bn128_fq<254>; 
    using value_type = policy_type::value_type;

    std::cout << "Field module value: " <<  policy_type::modulus << std::endl;

    value_type e1 = value_type(76749407), e2(44410867), e3 = value_type::one();

    std::cout << "Field element values: " << std::endl;
    std::cout << "e1 value: " <<  e1.data << std::endl;
    std::cout << "e2 value: " <<  e2.data << std::endl;
    std::cout << "e3 value: " <<  e3.data << std::endl;

    value_type e1e3 = e1 * e3, e1sqr = e1.square();

    std::cout << "e1 * e3 value: " <<  e1e3.data << std::endl;
    std::cout << "e1 square value: " <<  e1sqr.data << std::endl;

    std::cout << "e1 square square value: " <<  e1.square().square().data << std::endl;

    std::cout << "e1 pow 4 value: " <<  e1.pow(4).data << std::endl;    

}

int main()
{
   bn128_fq_number_examples();
   return 0;
}