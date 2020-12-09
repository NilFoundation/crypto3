//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#include <iostream>
#include <vector>

#include <boost/multiprecision/modular/modular_adaptor.hpp>
#include <boost/multiprecision/modular/modular_params.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_modular.hpp>

#include "test.hpp"

#include <boost/multiprecision/cpp_int/literals.hpp>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(130);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(1024);

using namespace boost::multiprecision;

int main()
{
   typedef cpp_int_backend<130, 130>         Backend;
   typedef number<modular_adaptor<Backend> > modular_number;
   typedef modular_params<Backend>           params_number;
   typedef number<Backend>                   standard_number;

   constexpr standard_number mod_s = 0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130;

   // constexpr standard_number a_s   = 0x379085f9a40f695d3558c21800f44753_cppui130;
   // constexpr standard_number b_s   = 0x24a0d0eece28cf91ebb3e9a746db228c_cppui130;
   constexpr standard_number a_s   = 0x17726cc3339b6035a1d30d80d1cbcdc_cppui130;
   constexpr standard_number b_s   = 0x1c4abfbdb6926bf87925b064d9ff190bc_cppui130;

   constexpr
       params_number mod_p(mod_s);
   constexpr
       modular_number a(a_s, mod_p);
   constexpr
       modular_number b(b_s, mod_p);

   constexpr
       modular_number a_plus_b = a + b;
   constexpr
      modular_number a_subt_b = a - b;
   constexpr
      modular_number a_mult_b = a * b;
   constexpr
      modular_number a_div_b = a / b;
   constexpr
      modular_number a_mod_b = a % b;

   // constexpr standard_number a_plus_b_s = 0x5c3156e8723838ef210cabbf47cf69df_cppui130;
   // constexpr standard_number a_subt_b_s = 0x12efb50ad5e699cb49a4d870ba1924c7_cppui130;
   // constexpr standard_number a_mult_b_s = 0xf47d3d496822f4806a15c741082a7ee4_cppui130;
   // constexpr standard_number a_div_b_s = 0x1_cppui130;
   // constexpr standard_number a_mod_b_s = 0x12efb50ad5e699cb49a4d870ba1924c7_cppui130;
   constexpr standard_number a_plus_b_s = 0x1c62322a79c60758aec783725ad0e4d98_cppui130;
   constexpr standard_number a_subt_b_s = 0x150dba68fc138eefb6851ca654a7a74db_cppui130;
   constexpr standard_number a_mult_b_s = 0xf3e365598398ba15b80251e9406d6111_cppui130;
   constexpr standard_number a_div_b_s = 0x0_cppui130;
   constexpr standard_number a_mod_b_s = 0x17726cc3339b6035a1d30d80d1cbcdc_cppui130;

   static_assert(a_plus_b == modular_number(a_plus_b_s, mod_p), "addition error");
   static_assert(a_subt_b == modular_number(a_subt_b_s, mod_p), "subtraction error");
   static_assert(a_mult_b == modular_number(a_mult_b_s, mod_p), "multiplication error");
   static_assert(a_div_b == modular_number(a_div_b_s, mod_p), "division error");
   static_assert(a_mod_b == modular_number(a_mod_b_s, mod_p), "mod error");

   static_assert((a > b) == (a_s > b_s), "g error");
   static_assert((a >= b) == (a_s >= b_s), "ge error");
   static_assert((a == b) == (a_s == b_s), "e error");
   static_assert((a < b) == (a_s < b_s), "l error");
   static_assert((a <= b) == (a_s <= b_s), "le error");
   static_assert((a != b) == (a_s != b_s), "ne error");

   static_assert(static_cast<modular_number>(a & b) == modular_number((a_s & b_s), mod_p), "and error");
   static_assert(static_cast<modular_number>(a | b) == modular_number((a_s | b_s), mod_p), "or error");
   static_assert(static_cast<modular_number>(a ^ b) == modular_number((a_s ^ b_s), mod_p), "xor error");

   static_assert(static_cast<modular_number>(pow(a, b)) == modular_number(powm(a_s, b_s, mod_s), mod_p), "pow error");
}
