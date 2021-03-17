//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

//[cpp_modular_eg
#include <iostream>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

template <class Modular, class Params>
void modular_number_examples()
{
   std::cout << "Pre-calculation parameters for module: " << std::endl;
   Params mod(7);
   std::cout << "Value mod: " << mod << std::endl;
   Modular a(4, 7), b(4, mod), c(9, mod), d(3, 4);
   std::cout << "Initialization a equal b: " << (a == b) << std::endl;
   std::cout << "Value a: " << a << std::endl;
   std::cout << "Value b: " << b << std::endl;
   std::cout << "Value c: " << c << std::endl;

   std::cout << "Some base function: " << std::endl;
   std::cout << "Add a and b: " << a + b << std::endl;
   std::cout << "Sub a and b: " << a - b << std::endl;
   std::cout << "Sub c and a ((-y mod x) equal ((x-y) mod x): " << c - a << std::endl;
   std::cout << "Multiply a and b: " << a * b << std::endl;
   std::cout << "Divide a and b: " << a / b << std::endl;
   std::cout << "Module a % b: " << a % b << std::endl;

   std::cout << "Some bitwise function: "  << std::endl;
   std::cout << "a and b: " << (a & b) << std::endl;
   std::cout << "a xor b: " << (a ^ b) << std::endl;
   std::cout << "a or b: " << (a | b) << std::endl;

   std::cout << "Pow function: " <<  std::endl;
   std::cout << "Pow a^b: " << pow(a, b) << std::endl;

   // bls12_381 fr module used
   Modular a1("0", "52435875175126190479447740508185965837690552500527637822603658699938581184513"),
       s("5357548122352420230771103151484263264414796060802659492954687376906409358208", "52435875175126190479447740508185965837690552500527637822603658699938581184513"),
       m_0_3("19672780149918614047617769345191063120834477401880138532514365439455403320407", "52435875175126190479447740508185965837690552500527637822603658699938581184513"),
       b1("23676453812739116229745200103713259707623838255070610943572937899456163562296", "52435875175126190479447740508185965837690552500527637822603658699938581184513");
   std::cout << a1 << std::endl;
   std::cout << s << std::endl;
   std::cout << m_0_3 << std::endl;
   std::cout << (s * m_0_3) << std::endl;
   std::cout << (a1 - s * m_0_3) << std::endl;
   std::cout << (a1 - b1) << std::endl;
}

int main()
{
   modular_number_examples<nil::crypto3::multiprecision::cpp_mod, nil::crypto3::multiprecision::cpp_mod_params>();
   return 0;
}

//]

/*

//[modular_out
Pre-calculation parameters for module: 
Value mod: 7
Initialization a equal b: 1
Value a: 4
Value b: 4
Value c: 2
Some base function: 
Add a and b: 1
Sub a and b: 0
Sub c and a ((-y mod x) equal ((x-y) mod x): 5
Multiply a and b: 2
Divide a and b: 1
Module a % b: 0
Some bitwise function: 
a and b: 4
a xor b: 0
a or b: 4
Pow function: 
Pow a^b: 4
//]
*/
