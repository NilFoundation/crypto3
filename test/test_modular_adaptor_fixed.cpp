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

#include <nil/crypto3/multiprecision/modular/modular_adaptor.hpp>
#include <nil/crypto3/multiprecision/modular/modular_params.hpp>
#include <nil/crypto3/multiprecision/inverse.hpp>

#include <nil/crypto3/multiprecision/cpp_int.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

#include "test.hpp"

#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>
#include <boost/type_traits/is_convertible.hpp>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(17);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(130);

using namespace nil::crypto3::multiprecision;

namespace boost {
    namespace test_tools {
        namespace tt_detail {
            template<template<typename, typename> class P, typename K, typename V>
            struct print_log_value<P<K, V>> {
                void operator()(std::ostream&, P<K, V> const&) {
                }
            };
        }    // namespace tt_detail
    }        // namespace test_tools
}    // namespace boost

enum test_set_enum : std::size_t {
    mod_e,
    a_e,
    b_e,
    // a_add_b_e, a_sub_b_e, a_mul_b_e, a_div_b_e, a_mod_b_e, a_pow_b_e,
    test_set_len
};

template<typename Backend, expression_template_option ExpressionTemplates>
constexpr void pow_test(const number<Backend, ExpressionTemplates>& a,
                        const number<Backend, ExpressionTemplates>& b,
                        const number<Backend, ExpressionTemplates>& m) {
    typedef number<Backend, ExpressionTemplates> standard_number;
    typedef modular_params<Backend> params_number;
    typedef number<modular_adaptor<Backend>> modular_number;

    params_number mod_p(m);
    // modular_params constructor
    modular_number a_m(a, mod_p);
    // number constructor
    modular_number b_m(b, m);

    standard_number a_powm_b = powm(a, b, m);
    // pow could be used only with modular_numbers
    modular_number a_m_pow_b_m = pow(a_m, b_m);
    // powm could be used with mixed types
    modular_number a_m_powm_b_m = powm(a_m, b_m);
    modular_number a_m_powm_b = powm(a_m, b);
    // if constexpr (backends::max_precision<Backend>::value <= bits_per_limb)
    // {
    //    limb_type e = b.template convert_to<limb_type>();
    //    modular_number  a_m_powm_e = powm(a_m, e);
    //    BOOST_ASSERT_MSG(a_m_powm_e.template convert_to<standard_number>() == a_powm_b, "powm error");
    // }

    BOOST_ASSERT_MSG(a_m_powm_b_m.template convert_to<standard_number>() == a_powm_b, "powm error");
    BOOST_ASSERT_MSG(a_m_powm_b.template convert_to<standard_number>() == a_powm_b, "powm error");
    BOOST_ASSERT_MSG(a_m_pow_b_m.template convert_to<standard_number>() == a_powm_b, "pow error");
}

// TODO: test_set is not ref because of constexpr error in gcc-10
template<typename Number>
constexpr bool base_operations_test(std::array<Number, test_set_len> test_set) {
    typedef typename Number::backend_type Backend;
    typedef typename default_ops::double_precision_type<Backend>::type Backend_doubled;
    typedef number<modular_adaptor<Backend>> modular_number;
    typedef modular_params<Backend> params_number;
    typedef Number standard_number;
    typedef number<Backend_doubled> dbl_standard_number;

    dbl_standard_number a_add_b_s =
        (static_cast<dbl_standard_number>(test_set[a_e]) + static_cast<dbl_standard_number>(test_set[b_e])) %
        test_set[mod_e];
    dbl_standard_number a_sub_b_s = (static_cast<dbl_standard_number>(test_set[a_e]) -
                                     static_cast<dbl_standard_number>(test_set[b_e]) + test_set[mod_e]) %
                                    test_set[mod_e];
    dbl_standard_number a_mul_b_s =
        (static_cast<dbl_standard_number>(test_set[a_e]) * static_cast<dbl_standard_number>(test_set[b_e])) %
        test_set[mod_e];
    dbl_standard_number a_div_b_s =
        (static_cast<dbl_standard_number>(test_set[a_e]) / static_cast<dbl_standard_number>(test_set[b_e])) %
        test_set[mod_e];
    dbl_standard_number a_mod_b_s =
        (static_cast<dbl_standard_number>(test_set[a_e]) % static_cast<dbl_standard_number>(test_set[b_e])) %
        test_set[mod_e];
    standard_number a_and_b_s = (test_set[a_e] & test_set[b_e]) % test_set[mod_e];
    standard_number a_or_b_s = (test_set[a_e] | test_set[b_e]) % test_set[mod_e];
    standard_number a_xor_b_s = (test_set[a_e] ^ test_set[b_e]) % test_set[mod_e];
    standard_number a_powm_b_s = powm(test_set[a_e], test_set[b_e], test_set[mod_e]);
    standard_number a_bit_set_s = test_set[a_e];
    bit_set(a_bit_set_s, 1);
    standard_number a_bit_unset_s = test_set[a_e];
    bit_unset(a_bit_unset_s, 2);
    standard_number a_bit_flip_s = test_set[a_e];
    bit_flip(a_bit_flip_s, 3);
    int b_msb_s = msb(test_set[b_e]);
    int b_lsb_s = lsb(test_set[b_e]);

    params_number mod_p(test_set[mod_e]);
    modular_number a(test_set[a_e], mod_p);
    modular_number b(test_set[b_e], mod_p);

    modular_number a_add_b = a + b;
    modular_number a_sub_b = a - b;
    modular_number a_mul_b = a * b;
    modular_number a_div_b = a / b;
    modular_number a_mod_b = a % b;
    modular_number a_and_b = a & b;
    modular_number a_or_b = a | b;
    modular_number a_xor_b = a ^ b;
    modular_number a_powm_b = powm(a, b);
    modular_number a_pow_b = pow(a, b);
    modular_number a_bit_set = a;
    bit_set(a_bit_set, 1);
    modular_number a_bit_unset = a;
    bit_unset(a_bit_unset, 2);
    modular_number a_bit_flip = a;
    bit_flip(a_bit_flip, 3);
    int b_msb = msb(test_set[b_e]);
    int b_lsb = lsb(test_set[b_e]);

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

    // BOOST_ASSERT_MSG(a_powm_b.template convert_to<standard_number>() == a_powm_b_s, "powm error");
    // BOOST_ASSERT_MSG(a_pow_b.template convert_to<standard_number>() == a_powm_b_s, "pow error");
    pow_test(test_set[a_e], test_set[b_e], test_set[mod_e]);

    BOOST_ASSERT_MSG(a_bit_set.template convert_to<standard_number>() == a_bit_set_s, "bit set error");
    BOOST_ASSERT_MSG(a_bit_unset.template convert_to<standard_number>() == a_bit_unset_s, "bit unset error");
    BOOST_ASSERT_MSG(a_bit_flip.template convert_to<standard_number>() == a_bit_flip_s, "bit flip error");

    BOOST_ASSERT_MSG(b_msb_s == b_msb, "msb error");
    BOOST_ASSERT_MSG(b_lsb_s == b_lsb, "lsb error");

    return true;
}

template<typename Number, std::size_t N, std::size_t enum_len>
constexpr bool base_operations_test(const std::array<std::array<Number, enum_len>, N>& test_data) {
    for (const auto& test_set : test_data) {
        base_operations_test(test_set);
    }
    return true;
}
template<bool>
class TD;
template<typename Number>
bool base_operations_test_mixed(const std::array<Number, test_set_len>& test_set) {
    typedef typename Number::backend_type Backend;
    typedef typename cpp_int::backend_type Backend_dynamic;
    typedef typename default_ops::double_precision_type<Backend>::type Backend_doubled;
    typedef number<modular_adaptor<Backend>> modular_number;
    typedef number<modular_adaptor<Backend_dynamic>> dynamic_modular_number;
    typedef modular_params<Backend> params_number;
    typedef modular_params<Backend_dynamic> dynamic_params_number;
    typedef Number standard_number;
    typedef cpp_int dynamic_number;

    dynamic_number a_add_b_s =
        (static_cast<dynamic_number>(test_set[a_e]) + static_cast<dynamic_number>(test_set[b_e])) % test_set[mod_e];
    dynamic_number a_sub_b_s =
        (static_cast<dynamic_number>(test_set[a_e]) - static_cast<dynamic_number>(test_set[b_e]) + test_set[mod_e]) %
        test_set[mod_e];
    dynamic_number a_mul_b_s =
        (static_cast<dynamic_number>(test_set[a_e]) * static_cast<dynamic_number>(test_set[b_e])) % test_set[mod_e];
    dynamic_number a_div_b_s =
        (static_cast<dynamic_number>(test_set[a_e]) / static_cast<dynamic_number>(test_set[b_e])) % test_set[mod_e];
    dynamic_number a_mod_b_s =
        (static_cast<dynamic_number>(test_set[a_e]) % static_cast<dynamic_number>(test_set[b_e])) % test_set[mod_e];
    dynamic_number a_and_b_s = (test_set[a_e] & test_set[b_e]) % test_set[mod_e];
    dynamic_number a_or_b_s = (test_set[a_e] | test_set[b_e]) % test_set[mod_e];
    dynamic_number a_xor_b_s = (test_set[a_e] ^ test_set[b_e]) % test_set[mod_e];
    dynamic_number a_powm_b_s = powm(test_set[a_e], test_set[b_e], test_set[mod_e]);

    params_number mod_p(test_set[mod_e]);
    modular_number a(test_set[a_e], mod_p);
    dynamic_modular_number b(test_set[b_e], mod_p);
    TD<boost::is_convertible<modular_number, dynamic_modular_number>::value> qwe;
    modular_number a_add_b = a + b;
    modular_number a_sub_b = a - b;
    modular_number a_mul_b = a * b;
    modular_number a_div_b = a / b;
    modular_number a_mod_b = a % b;
    modular_number a_and_b = a & b;
    modular_number a_or_b = a | b;
    modular_number a_xor_b = a ^ b;
    modular_number a_powm_b = powm(a, b);
    modular_number a_pow_b = pow(a, b);

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

template<typename Number, std::size_t N, std::size_t enum_len>
bool base_operations_test_mixed(const std::array<std::array<Number, enum_len>, N>& test_data) {
    for (const auto& test_set : test_data) {
        base_operations_test_mixed(test_set);
    }
    return true;
}

BOOST_AUTO_TEST_SUITE(static_tests)

BOOST_AUTO_TEST_CASE(base_ops_prime_mod_backend_130) {
    using Backend = cpp_int_backend<130, 130>;
    using standard_number = number<Backend>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 50>;
    constexpr test_data_t test_data = {{
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1902d38b6904893e90b9c5b8732d1f37d_cppui130,
         0x2b9060b88dea177d5213deb6f3794434_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x20de70b3f1426ef30b2b2c85d75e2ff2a_cppui130,
         0x1a50227dc3bd742a232db8798e16d1fbb_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2395c23e8da249dec864da20301b1b64a_cppui130,
         0xdf185b46a84f318f34160415cc2cc010_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x43c06149ee7c03529dc8a03d091b4e94_cppui130,
         0x310216180d322187af2c938af5a1ce59_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x26352a54193fd97c1b30ba3e4f624abf3_cppui130,
         0x271cc74f6ca6cb859a1c1420922eb29ae_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x55cc328d5cc8b9d3362664a61c49d05_cppui130,
         0x203c88f7c00196a19ca13f3956d823cf9_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2b7b43b1d5e1d838e06ac851dd57c2921_cppui130,
         0x1c3e4586b67511bdc48a424ab7934f3e2_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x71bff3e8b1dca8851adc38f3f7949f15_cppui130,
         0x1aa747f949397fd5dd7c8651e8150552_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1a2ce759cfc6960d663313054f1bb102f_cppui130,
         0xc7a66c97d85f5662ffeebbb953476196_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x29e2517b6b554a879c74e8c4e0516f177_cppui130,
         0x1f1218f45001011d29934c8cf15c52970_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x24633cbd7c7bfc5f2bd53ee68d61c35d2_cppui130,
         0x144cedf22adfea125bb43d0be11ca1d0c_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xfa48dc5dd7b4b1489220e933791b4338_cppui130,
         0x2b234e335952ad1681afa214a74622526_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x15b8a80d1056036fb5b43afa7acf2fba1_cppui130,
         0x20100f6e5147f7eae0dd456dcb21a8b57_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x11ad3e87c291c9ee81d50b80086315fff_cppui130,
         0x21f4e281ab8da64819ab4c2311bb5b18e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1cac9e60c8ba9fe1dd02a72bd7f302986_cppui130,
         0x1ca1068fbfa3b573d8f1f189dd5747a16_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1ed35770d0d86801f43eeb651aff88be9_cppui130,
         0x1906ec17bd1c75f7427c8c94bd7d1baa8_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x159635b82f84b811c9dd90d5cb6b178b_cppui130,
         0x140f2dea986ddcb181072cb9211f57a8d_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x27d6f0f737bacbce899e43dc682b5624d_cppui130,
         0x1011587e1de922107a18d7b925c77dd54_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x280f4c62adaa0ffd674affb50fe2e1695_cppui130,
         0x1d094e72b514dcbf1c711fdcf3e53cb8_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x6e5882e4497adbf5bb25efec29dfc7d8_cppui130,
         0x1a842e4abcdeedbc8abc583f41e46b125_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xdf8e9c5a1aef9fb8a84c47e4c13a8e32_cppui130,
         0x1a60dcd50617841662e100abea05666b4_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1f80459133a5f8b5049a346d931edca2e_cppui130,
         0x130fe586a5ec4e0045a6e16c4ebac2486_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1f284be48f9037159abfc1c11bd1e06e6_cppui130,
         0x31251cfead95629cb37cf61595785efa6_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x63766cb772cbaf3e4dfedffb2af6f181_cppui130,
         0x311d5240457feecb26f8c0e214a1bca75_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2ce5755bfe84b7cb37503711fe5585523_cppui130,
         0x1f028047ad558bd3208927b6644ae2ab9_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2bee37fdda5691f95381d391f9194f3f_cppui130,
         0xcbba87247175168e5d40dfb270b3427a_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x9bff8375de0961c15151ff7bc1c97589_cppui130,
         0x4ccf8b525bf3db5773680b031b007029_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2b861409455060d7b6a5e1d5f6c652548_cppui130,
         0x220fdc8a8d41a6ef2b2c0a1ec4569300b_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x239d57e467841c5247327e4eaa8d001f8_cppui130,
         0x10dfd3fb5b333abdaf5529542ce52b843_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x8c555f62b02b7f2c94987bd4e0c400a4_cppui130,
         0x326eaaaa17ba3ffef1b2622038e4277a_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2b7199f47c784514517cb65fbc3681820_cppui130,
         0x53368a9f4b547e43867c3b0fbbb55ba0_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1c867f8a6c7f7ba691baba7c34c8972c0_cppui130,
         0x18a36d27f551b90f3b70990c02be4040f_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xe08f32c086174483eb5c0fd194284789_cppui130,
         0x232cee45b9fafa3dd99b916f0da6b5b9f_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2fa93bf0d7dcdd1d2490b228602c11bc4_cppui130,
         0x313e75ddb32849fc2f920b7dac0784b8e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xfa23f38fe8ee768390a947885b402fbb_cppui130,
         0x1ed41f3daece99382858b91eb9341352_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x19046693c278bc3362c21e3369d28337b_cppui130,
         0x213100709424048752d19aaba00d597d2_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1c50381e9fe77faacbb4625d8a73454a9_cppui130,
         0x4c27748ded9d69446a518953eda5ea0c_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x19038fc207ecfca9a1a474489cd184a6d_cppui130,
         0xcf46092c1d5ccf5e41dff63f92c079b9_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x248e3a01cf8cd1147bfa3e5ed0b6e4a41_cppui130,
         0x7388310b8e62700604f76f2d45f98e52_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x282252b232f1c43f5f014529ee6e3134e_cppui130,
         0xc324f7242a9d93665f3f3d72bf731500_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x136d5cc4b596ecbacbcbea6385708cea8_cppui130,
         0x2eceb23b47b8beeb5cd704605f0102a27_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xa41d7a6deba861eb210e76fedf048120_cppui130,
         0x2b80b6fe5fce48e77bc6529a43670fa89_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0xbe044d7bc860898b4b67f2b0e47b2957_cppui130,
         0x1385abf4521b731a0ef6585e6fcbe1087_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x15431c536a4b40b7a2def9881b3ed3f65_cppui130,
         0x2c7a86a326513aec20b909a5b06e1d724_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x22dae6c3c21886db3a222b319df2fcc18_cppui130,
         0x29874fcdec2d26c29d56990f86e49921e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x1966a81455bb9ae791b06c79361cb04a9_cppui130,
         0x1ffebba8847893384f651589275aaceb1_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x2744dda0f21e9343d45d80cf7717947c4_cppui130,
         0x5559c5bfee5bdd51d7695f8be84aa7e0_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x217faf49e078d4f40e8bed99a20a4e3f4_cppui130,
         0x21e2c14e9f39cfdfc87a7eddbfa8de653_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x571a667c902421037c8d855907b904fd_cppui130,
         0x873f600a7769bf94aab70506e04d3dee_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130, 0x662ba0a5876b6f5f448563d9194ff704_cppui130,
         0xc88c6b7366ae5740e6860d5f1c906c00_cppui130},
    }};

    constexpr bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_CASE(base_ops_even_mod_backend_130) {
    using Backend = cpp_int_backend<130, 130>;
    using standard_number = number<Backend>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 50>;
    constexpr test_data_t test_data = {{
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xf6ce85e6f42595ffc6fcb50fdc3c9160_cppui130,
         0x2f04006a57e467c0d45f180da37f9a602_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x6d9d6fed00c44c3eaa674b2b86004106_cppui130,
         0x1f811a14b9a0ea15d873e532bb3364548_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1f72515d6e96f189c58447d4424da9cf5_cppui130,
         0x1cb8d94653cfbe79c97028957fd6b37d3_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x4c2fe1ff52320c73ec081a03082dfaf7_cppui130,
         0xb156219a04e9ac54ba60ce2d79d706eb_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xb6222e4281e459f84c0bd5d77ce3493_cppui130,
         0x32efd252fec869d766989d986cf31fc2_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1043b1bfcefc15dbe214d68e1061d8645_cppui130,
         0x43dede03370eb136ecbfa7ec396f0d6d_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x514c264f84ecf1c6e27d7c7c78e6b4a2_cppui130,
         0x2e9bae255ae7a67003d91da36a76615b8_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2ff3bee3f9723332a002b583133320c93_cppui130,
         0x25283c79b9b1e505f159c2fe560caffc9_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1446284dc17091cd19bf687b8bcfa8829_cppui130,
         0xc9e35084ad8092316a3ce0b77b61b998_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xc447bb62c4287d9f409ab060dae3ae92_cppui130,
         0x22efe8c2ac2188ad9e638d88bb4c754b5_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x313265520502bb48dceca31b17afa02f0_cppui130,
         0x109c4589d316e8ec374c1671ed51ee911_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2d639758db1ae7106138010f0e573079e_cppui130,
         0x268a07bc08a254c23c9d71e3303352c1b_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x20898a292ba2360df9b8f42651f342554_cppui130,
         0x13ea3770bbfab80ba966ddc255a419664_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x879758e1d55d9db504d0122b735255ac_cppui130,
         0x2287b16011ef333a67b1984c1f8d2aa55_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xeff14b264f211d251f3852bd87ebeae2_cppui130,
         0x1b5ebb5ef4a47e00cc6a801e5b383b69e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xc2723880d0678f28cd177e8792d5ed2d_cppui130,
         0x2a790884868d6fc5ef87d73d5b80ff46e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x28a83dffca1513a29489e8835d244d6c5_cppui130,
         0x15d4f2d8e0949e0aa82f178300c2da5d3_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x25ded52e8495fe687f442ab3579d22963_cppui130,
         0x2754bb6b9fb861566833f59229e28e0b1_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1ec91d30d83ac012534a9b7561f390be4_cppui130,
         0x308d7237b1cfb01b5ca9fa894ae3c6c48_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xa8b175970e5266b7575376c254c5ad4_cppui130,
         0x7bd2cb80c703ab2fe711022067a805f1_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x3068f458ab46abf38f3ab53368fefe1b3_cppui130,
         0x44da306ee50c5462b9910fcba033ec28_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x7347fcf946c50eb24121d2695a74138_cppui130,
         0x2cc6b5e5400509f854189e73f9e252331_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x13e5c415b09516c96134af94a77018a61_cppui130,
         0x4b1f1e72fb30cffbef1bbe88d8d6c25_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x157cedbd74cdd229f3b43e8ab59199092_cppui130,
         0x144db4073011653f19851e3b7231b8eb0_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xadbf28669d70f71efea08f2b7dcd3929_cppui130,
         0x2352ba5d47b493e545238dc33f8018555_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x3118fbf21bf8820849498b777ae4369c2_cppui130,
         0x8e3b38851b87235ab9e415c4f9973cb5_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2d87b88301585c45369f392edad58ebbb_cppui130,
         0x17b9f6b9257dc97b99d2b43da9a557a76_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2836115435665dffa299a2e1dba2bc02_cppui130,
         0x181aa88e10efd256cebb4563cbfb06436_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x4010011e94719b273a8f657daecb8154_cppui130,
         0x16aa3735374efa31f48b9f0b63eca9f1e_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xfd82a47f158cf4773e6177c3b9087ce1_cppui130,
         0x14686b4ba0accbb93c1fb046e69015338_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x662de620b44deb4469155819375bd2ae_cppui130,
         0xa1a7f7e023df7165ca899d4366bbc7f5_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xd12ea24d1261fc11787313ef5906f58d_cppui130,
         0x1c2a2731db836bc6156689cd762da9364_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x26d99465f1a39a64ef21a46d454161f24_cppui130,
         0x27c3ed62253a11d4dc15d370704817498_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2570d84dca037136829b41df4809e3810_cppui130,
         0x904beba3c2f174a54466d0bed0fb581b_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1183aa1a729def2d3c7138aae27332134_cppui130,
         0x208bc970b97cf55008c06fc620d025053_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xd8c70b07b915682a3d9f01ea5c51d34b_cppui130,
         0x6584051efd453ff081e2189928a9a9c4_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xa14b405e334ae992f920fb9373508696_cppui130,
         0x104aa2d49412388ae364af54a916fb501_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xe5f1875befdf2bc34c0ef450753afb87_cppui130,
         0x20f84732af830324ed3949c93704a0ce2_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x22dea1e18f9ec2bdb731db37bcab995ad_cppui130,
         0x1eb896b7179ab4a60a5cfb051c4f6805b_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x322c6c9cd1a662e0a20738db589ae298_cppui130,
         0x2872647f25d62d395a64406fdcf9ea04b_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xbfde51cd756d321a25d54a3909890edb_cppui130,
         0xbd2e612e27d726d58a8be3a643373147_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xb63cc77f71d194b5824946e44fe21831_cppui130,
         0x556942440de628a1b78d70b8ce61cad5_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x28b231976fbb6484e07f1c36b709811c6_cppui130,
         0x22da443e75ea4b64e4dd5b0e701948b9a_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2b564befbf84fb99e6d3e96a00e28a111_cppui130,
         0x2680850f06cffc374d3c98dac2a3522ca_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x19738eb221a6b1cc01159dac5232f5f94_cppui130,
         0x1888b0fd2c91a44559730f4772021e7ae_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x128cbc897d8a21f0924f0824cc0a2a2af_cppui130,
         0x1667817727b346d00cfe296b83099260a_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x1176a4938cafb93365f979e0648a9b36d_cppui130,
         0x1d424e90ed8b1d58a4e5f63a983f66b23_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0xe1d5e0b579b9ffabd79f55a3ad58095a_cppui130,
         0x28facaa806c45f06b33f90a25a256cb57_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x29492c8c9736c8b22abbe8cc151c0bbe5_cppui130,
         0x1e2e6cf551c64286202dbc4202eb950b4_cppui130},
        {0x314107b9ef725f87fa08f9fdadd4f48ba_cppui130, 0x2d38c6d88e4be77725f5a337fadacb890_cppui130,
         0x2b711aed3a4d108fd95d3a8c3338bf713_cppui130},
    }};

    constexpr bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_CASE(base_ops_even_mod_backend_17) {
    using Backend = cpp_int_backend<17, 17>;
    using standard_number = number<Backend>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 20>;
    constexpr test_data_t test_data = {{
        {0x1e240_cppui17, 0x3a97_cppui17, 0xc070_cppui17},   {0x1e240_cppui17, 0x1dea7_cppui17, 0x1aaab_cppui17},
        {0x1e240_cppui17, 0x1936f_cppui17, 0xfb0b_cppui17},  {0x1e240_cppui17, 0x13067_cppui17, 0x1566c_cppui17},
        {0x1e240_cppui17, 0x1b960_cppui17, 0x1773f_cppui17}, {0x1e240_cppui17, 0x101e4_cppui17, 0x156ca_cppui17},
        {0x1e240_cppui17, 0x167f3_cppui17, 0x13c52_cppui17}, {0x1e240_cppui17, 0xc536_cppui17, 0x14c8e_cppui17},
        {0x1e240_cppui17, 0xed02_cppui17, 0x1dafc_cppui17},  {0x1e240_cppui17, 0x126a6_cppui17, 0x18a8b_cppui17},
        {0x1e240_cppui17, 0x111ac_cppui17, 0x94c2_cppui17},  {0x1e240_cppui17, 0x3a03_cppui17, 0x89d8_cppui17},
        {0x1e240_cppui17, 0x3add_cppui17, 0x101ae_cppui17},  {0x1e240_cppui17, 0x8db4_cppui17, 0x50e2_cppui17},
        {0x1e240_cppui17, 0x1bab_cppui17, 0x1d5f6_cppui17},  {0x1e240_cppui17, 0x144dc_cppui17, 0x172f8_cppui17},
        {0x1e240_cppui17, 0x1cd30_cppui17, 0x1a5c_cppui17},  {0x1e240_cppui17, 0x13c3d_cppui17, 0x4358_cppui17},
        {0x1e240_cppui17, 0x18d68_cppui17, 0x1299d_cppui17}, {0x1e240_cppui17, 0x10153_cppui17, 0x2c8a_cppui17},
    }};

    constexpr bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_CASE(base_ops_odd_mod_backend_17) {
    using Backend = cpp_int_backend<17, 17>;
    using standard_number = number<Backend>;
    using test_set = std::array<standard_number, test_set_len>;
    using test_data_t = std::array<test_set, 20>;
    constexpr test_data_t test_data = {{
        {0x1e241_cppui17, 0x3a97_cppui17, 0xc070_cppui17},   {0x1e241_cppui17, 0x1dea7_cppui17, 0x1aaab_cppui17},
        {0x1e241_cppui17, 0x1936f_cppui17, 0xfb0b_cppui17},  {0x1e241_cppui17, 0x13067_cppui17, 0x1566c_cppui17},
        {0x1e241_cppui17, 0x1b960_cppui17, 0x1773f_cppui17}, {0x1e241_cppui17, 0x101e4_cppui17, 0x156ca_cppui17},
        {0x1e241_cppui17, 0x167f3_cppui17, 0x13c52_cppui17}, {0x1e241_cppui17, 0xc536_cppui17, 0x14c8e_cppui17},
        {0x1e241_cppui17, 0xed02_cppui17, 0x1dafc_cppui17},  {0x1e241_cppui17, 0x126a6_cppui17, 0x18a8b_cppui17},
        {0x1e241_cppui17, 0x111ac_cppui17, 0x94c2_cppui17},  {0x1e241_cppui17, 0x3a03_cppui17, 0x89d8_cppui17},
        {0x1e241_cppui17, 0x3add_cppui17, 0x101ae_cppui17},  {0x1e241_cppui17, 0x8db4_cppui17, 0x50e2_cppui17},
        {0x1e241_cppui17, 0x1bab_cppui17, 0x1d5f6_cppui17},  {0x1e241_cppui17, 0x144dc_cppui17, 0x172f8_cppui17},
        {0x1e241_cppui17, 0x1cd30_cppui17, 0x1a5c_cppui17},  {0x1e241_cppui17, 0x13c3d_cppui17, 0x4358_cppui17},
        {0x1e241_cppui17, 0x18d68_cppui17, 0x1299d_cppui17}, {0x1e241_cppui17, 0x10153_cppui17, 0x2c8a_cppui17},
    }};

    constexpr bool res = base_operations_test(test_data);
}

BOOST_AUTO_TEST_SUITE_END()

// BOOST_AUTO_TEST_SUITE(runtime_tests)
//
// BOOST_AUTO_TEST_CASE(base_ops_prime_mod_backend_130_mixed)
// {
//    using Backend         = cpp_int_backend<130, 130>;
//    using standard_number = number<Backend>;
//    using test_set        = std::array<standard_number, test_set_len>;
//    using test_data_t     = std::array<test_set, 50>;
//    test_data_t test_data = {{
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1902d38b6904893e90b9c5b8732d1f37d_cppui130,
//                                     0x2b9060b88dea177d5213deb6f3794434_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x20de70b3f1426ef30b2b2c85d75e2ff2a_cppui130,
//                                     0x1a50227dc3bd742a232db8798e16d1fbb_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2395c23e8da249dec864da20301b1b64a_cppui130,
//                                     0xdf185b46a84f318f34160415cc2cc010_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x43c06149ee7c03529dc8a03d091b4e94_cppui130,
//                                     0x310216180d322187af2c938af5a1ce59_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x26352a54193fd97c1b30ba3e4f624abf3_cppui130,
//                                     0x271cc74f6ca6cb859a1c1420922eb29ae_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x55cc328d5cc8b9d3362664a61c49d05_cppui130,
//                                     0x203c88f7c00196a19ca13f3956d823cf9_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2b7b43b1d5e1d838e06ac851dd57c2921_cppui130,
//                                     0x1c3e4586b67511bdc48a424ab7934f3e2_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x71bff3e8b1dca8851adc38f3f7949f15_cppui130,
//                                     0x1aa747f949397fd5dd7c8651e8150552_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1a2ce759cfc6960d663313054f1bb102f_cppui130,
//                                     0xc7a66c97d85f5662ffeebbb953476196_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x29e2517b6b554a879c74e8c4e0516f177_cppui130,
//                                     0x1f1218f45001011d29934c8cf15c52970_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x24633cbd7c7bfc5f2bd53ee68d61c35d2_cppui130,
//                                     0x144cedf22adfea125bb43d0be11ca1d0c_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xfa48dc5dd7b4b1489220e933791b4338_cppui130,
//                                     0x2b234e335952ad1681afa214a74622526_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x15b8a80d1056036fb5b43afa7acf2fba1_cppui130,
//                                     0x20100f6e5147f7eae0dd456dcb21a8b57_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x11ad3e87c291c9ee81d50b80086315fff_cppui130,
//                                     0x21f4e281ab8da64819ab4c2311bb5b18e_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1cac9e60c8ba9fe1dd02a72bd7f302986_cppui130,
//                                     0x1ca1068fbfa3b573d8f1f189dd5747a16_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1ed35770d0d86801f43eeb651aff88be9_cppui130,
//                                     0x1906ec17bd1c75f7427c8c94bd7d1baa8_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x159635b82f84b811c9dd90d5cb6b178b_cppui130,
//                                     0x140f2dea986ddcb181072cb9211f57a8d_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x27d6f0f737bacbce899e43dc682b5624d_cppui130,
//                                     0x1011587e1de922107a18d7b925c77dd54_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x280f4c62adaa0ffd674affb50fe2e1695_cppui130,
//                                     0x1d094e72b514dcbf1c711fdcf3e53cb8_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x6e5882e4497adbf5bb25efec29dfc7d8_cppui130,
//                                     0x1a842e4abcdeedbc8abc583f41e46b125_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xdf8e9c5a1aef9fb8a84c47e4c13a8e32_cppui130,
//                                     0x1a60dcd50617841662e100abea05666b4_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1f80459133a5f8b5049a346d931edca2e_cppui130,
//                                     0x130fe586a5ec4e0045a6e16c4ebac2486_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1f284be48f9037159abfc1c11bd1e06e6_cppui130,
//                                     0x31251cfead95629cb37cf61595785efa6_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x63766cb772cbaf3e4dfedffb2af6f181_cppui130,
//                                     0x311d5240457feecb26f8c0e214a1bca75_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2ce5755bfe84b7cb37503711fe5585523_cppui130,
//                                     0x1f028047ad558bd3208927b6644ae2ab9_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2bee37fdda5691f95381d391f9194f3f_cppui130,
//                                     0xcbba87247175168e5d40dfb270b3427a_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x9bff8375de0961c15151ff7bc1c97589_cppui130,
//                                     0x4ccf8b525bf3db5773680b031b007029_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2b861409455060d7b6a5e1d5f6c652548_cppui130,
//                                     0x220fdc8a8d41a6ef2b2c0a1ec4569300b_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x239d57e467841c5247327e4eaa8d001f8_cppui130,
//                                     0x10dfd3fb5b333abdaf5529542ce52b843_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x8c555f62b02b7f2c94987bd4e0c400a4_cppui130,
//                                     0x326eaaaa17ba3ffef1b2622038e4277a_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2b7199f47c784514517cb65fbc3681820_cppui130,
//                                     0x53368a9f4b547e43867c3b0fbbb55ba0_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1c867f8a6c7f7ba691baba7c34c8972c0_cppui130,
//                                     0x18a36d27f551b90f3b70990c02be4040f_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xe08f32c086174483eb5c0fd194284789_cppui130,
//                                     0x232cee45b9fafa3dd99b916f0da6b5b9f_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2fa93bf0d7dcdd1d2490b228602c11bc4_cppui130,
//                                     0x313e75ddb32849fc2f920b7dac0784b8e_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xfa23f38fe8ee768390a947885b402fbb_cppui130,
//                                     0x1ed41f3daece99382858b91eb9341352_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x19046693c278bc3362c21e3369d28337b_cppui130,
//                                     0x213100709424048752d19aaba00d597d2_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1c50381e9fe77faacbb4625d8a73454a9_cppui130,
//                                     0x4c27748ded9d69446a518953eda5ea0c_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x19038fc207ecfca9a1a474489cd184a6d_cppui130,
//                                     0xcf46092c1d5ccf5e41dff63f92c079b9_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x248e3a01cf8cd1147bfa3e5ed0b6e4a41_cppui130,
//                                     0x7388310b8e62700604f76f2d45f98e52_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x282252b232f1c43f5f014529ee6e3134e_cppui130,
//                                     0xc324f7242a9d93665f3f3d72bf731500_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x136d5cc4b596ecbacbcbea6385708cea8_cppui130,
//                                     0x2eceb23b47b8beeb5cd704605f0102a27_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xa41d7a6deba861eb210e76fedf048120_cppui130,
//                                     0x2b80b6fe5fce48e77bc6529a43670fa89_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0xbe044d7bc860898b4b67f2b0e47b2957_cppui130,
//                                     0x1385abf4521b731a0ef6585e6fcbe1087_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x15431c536a4b40b7a2def9881b3ed3f65_cppui130,
//                                     0x2c7a86a326513aec20b909a5b06e1d724_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x22dae6c3c21886db3a222b319df2fcc18_cppui130,
//                                     0x29874fcdec2d26c29d56990f86e49921e_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x1966a81455bb9ae791b06c79361cb04a9_cppui130,
//                                     0x1ffebba8847893384f651589275aaceb1_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x2744dda0f21e9343d45d80cf7717947c4_cppui130,
//                                     0x5559c5bfee5bdd51d7695f8be84aa7e0_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x217faf49e078d4f40e8bed99a20a4e3f4_cppui130,
//                                     0x21e2c14e9f39cfdfc87a7eddbfa8de653_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x571a667c902421037c8d855907b904fd_cppui130,
//                                     0x873f600a7769bf94aab70506e04d3dee_cppui130},
//                                 {0x314107b9ef725f87fa08f9fdadd4f48bb_cppui130,
//                                     0x662ba0a5876b6f5f448563d9194ff704_cppui130,
//                                     0xc88c6b7366ae5740e6860d5f1c906c00_cppui130},
//                             }};
//
//    bool res = base_operations_test_mixed(test_data);
// }
//
// BOOST_AUTO_TEST_SUITE_END()
