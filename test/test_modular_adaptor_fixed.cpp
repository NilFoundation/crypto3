//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE modular_fixed_multiprecision_test

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

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

using namespace boost::multiprecision;

namespace boost {
namespace test_tools {
namespace tt_detail {
template <template <typename, typename> class P, typename K, typename V>
struct print_log_value<P<K, V> >
{
   void operator()(std::ostream&, P<K, V> const&)
   {
   }
};
}
}
}    // namespace boost

enum test_set_enum : std::size_t
{
   mod_e,
   a_e,
   b_e,
   // a_add_b_e, a_sub_b_e, a_mul_b_e, a_div_b_e, a_mod_b_e, a_pow_b_e,
   set_len
};

// TODO: test_set is not ref because of constexpr error in gcc-10
template <typename Number>
constexpr bool base_operations_test(std::array<Number, set_len> test_set)
{
   typedef typename Number::backend_type                              Backend;
   typedef typename default_ops::double_precision_type<Backend>::type Backend_doubled;
   typedef number<modular_adaptor<Backend> >                          modular_number;
   typedef modular_params<Backend>                                    params_number;
   typedef Number                                                     standard_number;
   typedef number<Backend_doubled>                                    dbl_standard_number;

   dbl_standard_number a_add_b_s  = (static_cast<dbl_standard_number>(test_set[a_e]) + static_cast<dbl_standard_number>(test_set[b_e])) % test_set[mod_e];
   dbl_standard_number a_sub_b_s  = (static_cast<dbl_standard_number>(test_set[a_e]) - static_cast<dbl_standard_number>(test_set[b_e]) + test_set[mod_e]) % test_set[mod_e];
   dbl_standard_number a_mul_b_s  = (static_cast<dbl_standard_number>(test_set[a_e]) * static_cast<dbl_standard_number>(test_set[b_e])) % test_set[mod_e];
   dbl_standard_number a_div_b_s  = (static_cast<dbl_standard_number>(test_set[a_e]) / static_cast<dbl_standard_number>(test_set[b_e])) % test_set[mod_e];
   dbl_standard_number a_mod_b_s  = (static_cast<dbl_standard_number>(test_set[a_e]) % static_cast<dbl_standard_number>(test_set[b_e])) % test_set[mod_e];
   standard_number     a_and_b_s  = (test_set[a_e] & test_set[b_e]) % test_set[mod_e];
   standard_number     a_or_b_s   = (test_set[a_e] | test_set[b_e]) % test_set[mod_e];
   standard_number     a_xor_b_s  = (test_set[a_e] ^ test_set[b_e]) % test_set[mod_e];
   standard_number     a_powm_b_s = powm(test_set[a_e], test_set[b_e], test_set[mod_e]);

   params_number  mod_p(test_set[mod_e]);
   modular_number a(test_set[a_e], mod_p);
   modular_number b(test_set[b_e], mod_p);

   modular_number a_add_b  = a + b;
   modular_number a_sub_b  = a - b;
   modular_number a_mul_b  = a * b;
   modular_number a_div_b  = a / b;
   modular_number a_mod_b  = a % b;
   modular_number a_and_b  = a & b;
   modular_number a_or_b   = a | b;
   modular_number a_xor_b  = a ^ b;
   modular_number a_powm_b = powm(a, b);
   modular_number a_pow_b  = pow(a, b);

   BOOST_ASSERT_MSG(a_add_b.template convert_to<standard_number>() == a_add_b_s, "addition error");
   BOOST_ASSERT_MSG(a_sub_b.template convert_to<standard_number>() == a_sub_b_s, "subtraction error");
   BOOST_ASSERT_MSG(a_mul_b.template convert_to<standard_number>() == a_mul_b_s, "multiplication error");
   BOOST_ASSERT_MSG(a_div_b.template convert_to<standard_number>() == a_div_b_s, "division error");
   BOOST_ASSERT_MSG(a_mod_b.template convert_to<standard_number>() == a_mod_b_s, "mod error");

   BOOST_ASSERT_MSG((a > b) == (test_set[a_e] > test_set[b_e]), "g error");
   BOOST_ASSERT_MSG((a >= b) == (test_set[a_e] >= test_set[b_e]), "ge error");
   BOOST_ASSERT_MSG((a == b) == (test_set[a_e] == test_set[b_e]), "e error");
   BOOST_ASSERT_MSG((a < b) == (test_set[a_e] < test_set[b_e]), "l error");
   BOOST_ASSERT_MSG((a <= b) == (test_set[a_e] <= test_set[b_e]), "le error");
   BOOST_ASSERT_MSG((a != b) == (test_set[a_e] != test_set[b_e]), "ne error");

   BOOST_ASSERT_MSG(a_and_b.template convert_to<standard_number>() == a_and_b_s, "and error");
   BOOST_ASSERT_MSG(a_or_b.template convert_to<standard_number>() == a_or_b_s, "or error");
   BOOST_ASSERT_MSG(a_xor_b.template convert_to<standard_number>() == a_xor_b_s, "xor error");

   BOOST_ASSERT_MSG(a_powm_b.template convert_to<standard_number>() == a_powm_b_s, "powm error");
   BOOST_ASSERT_MSG(a_pow_b.template convert_to<standard_number>() == a_powm_b_s, "pow error");

   return true;
}

template <typename Number, std::size_t N, std::size_t enum_len>
constexpr bool base_operations_test(const std::array<std::array<Number, enum_len>, N>& test_data)
{
   for (const auto& test_set : test_data)
   {
      base_operations_test(test_set);
   }
   return true;
}

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(base_ops_prime_mod_backend_130)
{
   using Backend         = cpp_int_backend<130, 130>;
   using standard_number = number<Backend>;
   using test_set        = std::array<standard_number, set_len>;
   using test_data_t     = std::array<test_set, 50>;
   constexpr
       test_data_t test_data = {{
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1902d38b6904893e90b9c5b8732d1f37d_cppui130,
            0x2b9060b88dea177d5213deb6f3794434_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x20de70b3f1426ef30b2b2c85d75e2ff2a_cppui130,
            0x1a50227dc3bd742a232db8798e16d1fbb_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2395c23e8da249dec864da20301b1b64a_cppui130,
            0xdf185b46a84f318f34160415cc2cc010_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x43c06149ee7c03529dc8a03d091b4e94_cppui130,
            0x310216180d322187af2c938af5a1ce59_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x26352a54193fd97c1b30ba3e4f624abf3_cppui130,
            0x271cc74f6ca6cb859a1c1420922eb29ae_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x55cc328d5cc8b9d3362664a61c49d05_cppui130,
            0x203c88f7c00196a19ca13f3956d823cf9_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2b7b43b1d5e1d838e06ac851dd57c2921_cppui130,
            0x1c3e4586b67511bdc48a424ab7934f3e2_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x71bff3e8b1dca8851adc38f3f7949f15_cppui130,
            0x1aa747f949397fd5dd7c8651e8150552_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1a2ce759cfc6960d663313054f1bb102f_cppui130,
            0xc7a66c97d85f5662ffeebbb953476196_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x29e2517b6b554a879c74e8c4e0516f177_cppui130,
            0x1f1218f45001011d29934c8cf15c52970_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x24633cbd7c7bfc5f2bd53ee68d61c35d2_cppui130,
            0x144cedf22adfea125bb43d0be11ca1d0c_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xfa48dc5dd7b4b1489220e933791b4338_cppui130,
            0x2b234e335952ad1681afa214a74622526_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x15b8a80d1056036fb5b43afa7acf2fba1_cppui130,
            0x20100f6e5147f7eae0dd456dcb21a8b57_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x11ad3e87c291c9ee81d50b80086315fff_cppui130,
            0x21f4e281ab8da64819ab4c2311bb5b18e_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1cac9e60c8ba9fe1dd02a72bd7f302986_cppui130,
            0x1ca1068fbfa3b573d8f1f189dd5747a16_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1ed35770d0d86801f43eeb651aff88be9_cppui130,
            0x1906ec17bd1c75f7427c8c94bd7d1baa8_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x159635b82f84b811c9dd90d5cb6b178b_cppui130,
            0x140f2dea986ddcb181072cb9211f57a8d_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x27d6f0f737bacbce899e43dc682b5624d_cppui130,
            0x1011587e1de922107a18d7b925c77dd54_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x280f4c62adaa0ffd674affb50fe2e1695_cppui130,
            0x1d094e72b514dcbf1c711fdcf3e53cb8_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x6e5882e4497adbf5bb25efec29dfc7d8_cppui130,
            0x1a842e4abcdeedbc8abc583f41e46b125_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xdf8e9c5a1aef9fb8a84c47e4c13a8e32_cppui130,
            0x1a60dcd50617841662e100abea05666b4_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1f80459133a5f8b5049a346d931edca2e_cppui130,
            0x130fe586a5ec4e0045a6e16c4ebac2486_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1f284be48f9037159abfc1c11bd1e06e6_cppui130,
            0x31251cfead95629cb37cf61595785efa6_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x63766cb772cbaf3e4dfedffb2af6f181_cppui130,
            0x311d5240457feecb26f8c0e214a1bca75_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2ce5755bfe84b7cb37503711fe5585523_cppui130,
            0x1f028047ad558bd3208927b6644ae2ab9_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2bee37fdda5691f95381d391f9194f3f_cppui130,
            0xcbba87247175168e5d40dfb270b3427a_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x9bff8375de0961c15151ff7bc1c97589_cppui130,
            0x4ccf8b525bf3db5773680b031b007029_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2b861409455060d7b6a5e1d5f6c652548_cppui130,
            0x220fdc8a8d41a6ef2b2c0a1ec4569300b_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x239d57e467841c5247327e4eaa8d001f8_cppui130,
            0x10dfd3fb5b333abdaf5529542ce52b843_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x8c555f62b02b7f2c94987bd4e0c400a4_cppui130,
            0x326eaaaa17ba3ffef1b2622038e4277a_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2b7199f47c784514517cb65fbc3681820_cppui130,
            0x53368a9f4b547e43867c3b0fbbb55ba0_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1c867f8a6c7f7ba691baba7c34c8972c0_cppui130,
            0x18a36d27f551b90f3b70990c02be4040f_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xe08f32c086174483eb5c0fd194284789_cppui130,
            0x232cee45b9fafa3dd99b916f0da6b5b9f_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2fa93bf0d7dcdd1d2490b228602c11bc4_cppui130,
            0x313e75ddb32849fc2f920b7dac0784b8e_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xfa23f38fe8ee768390a947885b402fbb_cppui130,
            0x1ed41f3daece99382858b91eb9341352_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x19046693c278bc3362c21e3369d28337b_cppui130,
            0x213100709424048752d19aaba00d597d2_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1c50381e9fe77faacbb4625d8a73454a9_cppui130,
            0x4c27748ded9d69446a518953eda5ea0c_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x19038fc207ecfca9a1a474489cd184a6d_cppui130,
            0xcf46092c1d5ccf5e41dff63f92c079b9_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x248e3a01cf8cd1147bfa3e5ed0b6e4a41_cppui130,
            0x7388310b8e62700604f76f2d45f98e52_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x282252b232f1c43f5f014529ee6e3134e_cppui130,
            0xc324f7242a9d93665f3f3d72bf731500_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x136d5cc4b596ecbacbcbea6385708cea8_cppui130,
            0x2eceb23b47b8beeb5cd704605f0102a27_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xa41d7a6deba861eb210e76fedf048120_cppui130,
            0x2b80b6fe5fce48e77bc6529a43670fa89_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0xbe044d7bc860898b4b67f2b0e47b2957_cppui130,
            0x1385abf4521b731a0ef6585e6fcbe1087_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x15431c536a4b40b7a2def9881b3ed3f65_cppui130,
            0x2c7a86a326513aec20b909a5b06e1d724_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x22dae6c3c21886db3a222b319df2fcc18_cppui130,
            0x29874fcdec2d26c29d56990f86e49921e_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x1966a81455bb9ae791b06c79361cb04a9_cppui130,
            0x1ffebba8847893384f651589275aaceb1_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x2744dda0f21e9343d45d80cf7717947c4_cppui130,
            0x5559c5bfee5bdd51d7695f8be84aa7e0_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x217faf49e078d4f40e8bed99a20a4e3f4_cppui130,
            0x21e2c14e9f39cfdfc87a7eddbfa8de653_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x571a667c902421037c8d855907b904fd_cppui130,
            0x873f600a7769bf94aab70506e04d3dee_cppui130},
           {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
            0x662ba0a5876b6f5f448563d9194ff704_cppui130,
            0xc88c6b7366ae5740e6860d5f1c906c00_cppui130},
       }};

   constexpr bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_SUITE_END()
