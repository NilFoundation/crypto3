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
#include <boost/multiprecision/inverse.hpp>

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

   constexpr standard_number a1_s   = 0x379085f9a40f695d3558c21800f44753_cppui130;
   constexpr standard_number b1_s   = 0x24a0d0eece28cf91ebb3e9a746db228c_cppui130;

   constexpr standard_number a2_s   = 0x17726cc3339b6035a1d30d80d1cbcdc_cppui130;
   constexpr standard_number b2_s   = 0x1c4abfbdb6926bf87925b064d9ff190bc_cppui130;


   constexpr
       params_number mod_p(mod_s);

   constexpr
       modular_number a1(a1_s, mod_p);
   constexpr
       modular_number b1(b1_s, mod_p);

   constexpr
      modular_number a2(a2_s, mod_p);
   constexpr
      modular_number b2(b2_s, mod_p);


   constexpr
       modular_number a1_plus_b1 = a1 + b1;
   constexpr
      modular_number a1_subt_b1 = a1 - b1;
   constexpr
      modular_number a1_mult_b1 = a1 * b1;
   constexpr
      modular_number a1_div_b1 = a1 / b1;
   constexpr
      modular_number a1_mod_b1 = a1 % b1;

   constexpr
      modular_number a2_plus_b2 = a2 + b2;
   constexpr
      modular_number a2_subt_b2 = a2 - b2;
   constexpr
      modular_number a2_mult_b2 = a2 * b2;
   constexpr
      modular_number a2_div_b2 = a2 / b2;
   constexpr
      modular_number a2_mod_b2 = a2 % b2;


   constexpr standard_number a1_plus_b1_s = 0x5c3156e8723838ef210cabbf47cf69df_cppui130;
   constexpr standard_number a1_subt_b1_s = 0x12efb50ad5e699cb49a4d870ba1924c7_cppui130;
   constexpr standard_number a1_mult_b1_s = 0xf47d3d496822f4806a15c741082a7ee4_cppui130;
   constexpr standard_number a1_div_b1_s = 0x1_cppui130;
   constexpr standard_number a1_mod_b1_s = 0x12efb50ad5e699cb49a4d870ba1924c7_cppui130;

   constexpr standard_number a2_plus_b2_s = 0x1c62322a79c60758aec783725ad0e4d98_cppui130;
   constexpr standard_number a2_subt_b2_s = 0x150dba68fc138eefb6851ca654a7a74db_cppui130;
   constexpr standard_number a2_mult_b2_s = 0xf3e365598398ba15b80251e9406d6111_cppui130;
   constexpr standard_number a2_div_b2_s = 0x0_cppui130;
   constexpr standard_number a2_mod_b2_s = 0x17726cc3339b6035a1d30d80d1cbcdc_cppui130;


   static_assert(a1_plus_b1.convert_to<standard_number>() == a1_plus_b1_s, "addition error");
   static_assert(a1_subt_b1.convert_to<standard_number>() == a1_subt_b1_s, "subtraction error");
   static_assert(a1_mult_b1.convert_to<standard_number>() == a1_mult_b1_s, "multiplication error");
   static_assert(a1_div_b1.convert_to<standard_number>() == a1_div_b1_s, "division error");
   static_assert(a1_mod_b1.convert_to<standard_number>() == a1_mod_b1_s, "mod error");

   static_assert(a2_plus_b2.convert_to<standard_number>() == a2_plus_b2_s, "addition error");
   static_assert(a2_subt_b2.convert_to<standard_number>() == a2_subt_b2_s, "subtraction error");
   static_assert(a2_mult_b2.convert_to<standard_number>() == a2_mult_b2_s, "multiplication error");
   static_assert(a2_div_b2.convert_to<standard_number>() == a2_div_b2_s, "division error");
   static_assert(a2_mod_b2.convert_to<standard_number>() == a2_mod_b2_s, "mod error");


   static_assert((a1 > b1) == (a1_s > b1_s), "g error");
   static_assert((a1 >= b1) == (a1_s >= b1_s), "ge error");
   static_assert((a1 == b1) == (a1_s == b1_s), "e error");
   static_assert((a1 < b1) == (a1_s < b1_s), "l error");
   static_assert((a1 <= b1) == (a1_s <= b1_s), "le error");
   static_assert((a1 != b1) == (a1_s != b1_s), "ne error");

   static_assert((a2 > b2) == (a2_s > b2_s), "g error");
   static_assert((a2 >= b2) == (a2_s >= b2_s), "ge error");
   static_assert((a2 == b2) == (a2_s == b2_s), "e error");
   static_assert((a2 < b2) == (a2_s < b2_s), "l error");
   static_assert((a2 <= b2) == (a2_s <= b2_s), "le error");
   static_assert((a2 != b2) == (a2_s != b2_s), "ne error");


   static_assert(static_cast<modular_number>(a1 & b1).convert_to<standard_number>() == (a1_s & b1_s), "and error");
   static_assert(static_cast<modular_number>(a1 | b1).convert_to<standard_number>() == (a1_s | b1_s), "or error");
   static_assert(static_cast<modular_number>(a1 ^ b1).convert_to<standard_number>() == (a1_s ^ b1_s), "xor error");

   static_assert(static_cast<modular_number>(a2 & b2).convert_to<standard_number>() == (a2_s & b2_s), "and error");
   static_assert(static_cast<modular_number>(a2 | b2).convert_to<standard_number>() == (a2_s | b2_s), "or error");
   static_assert(static_cast<modular_number>(a2 ^ b2).convert_to<standard_number>() == (a2_s ^ b2_s), "xor error");

   constexpr
       standard_number a1_pow_b1_s = powm(a1_s, b1_s, mod_s);
   constexpr
       modular_number a1_pow_b1 = powm(a1, b1);
   static_assert(static_cast<modular_number>(a1_pow_b1).convert_to<standard_number>() == a1_pow_b1_s, "pow error");

   // constexpr standard_number a_inv_s = 0x2d737afc03a2903fc9db7258fcd1d4147_cppui130;
   // constexpr standard_number a_inv_s = 0x8af50c75763b7a581c9b1df83a6f245a_cppui130;

   // constexpr
   //    modular_number a_inv = inverse_extended_euclidean_algorithm(a);
   //
   // static_assert(a_inv == modular_number(a_inv_s, mod_p), "");
}
