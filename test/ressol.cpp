//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE ressol_multiprecision_test

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/cpp_modular.hpp>

#include <nil/crypto3/multiprecision/ressol.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>

using namespace boost::multiprecision;

BOOST_AUTO_TEST_SUITE(ressol_runtime_tests)

BOOST_AUTO_TEST_CASE(ressol_runtime_4_bit_tests) {
    using T = number<cpp_int_modular_backend<4>>;
    using namespace boost::multiprecision;
    BOOST_CHECK_EQUAL(ressol(T(0u), T(11u)), 0u);
    BOOST_CHECK_EQUAL(ressol(T(5u), T(11u)), 4u);

    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(10u), T(11u)), 0u);
    BOOST_CHECK_EQUAL(ressol(T(2u), T(11u)), 0u);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_521_bit_tests) {
    using T = number<cpp_int_modular_backend<521>>;
    BOOST_CHECK_EQUAL(ressol(T(5u),
                             T("686479766013060971498190079908139321726943530014330540939446345918554318339765605212255"
                               "9640661454554977296311391480858037121987999716643812574028291115057151")),
                      T("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021539968"
                        "609345897897688700798659762992302941280478805021587896033442584"));

    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(4),
                             T("686479766013060971498190079908139321726943530014330540939446345918554318339765605212255"
                               "9640661454554977296311391480858037121987999716643812574028291115057149")),
                      0);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_224_bit_tests) {
    using T = number<cpp_int_modular_backend<224>>;
    BOOST_CHECK_EQUAL(ressol(T("20749193632488214633180774027217139706413443729200940480695355894185"),
                             T("26959946667150639794667015087019630673557916260026308143510066298881")),
                      T("1825097171398375765346899906888660610489759292065918530856859649959"));
}

BOOST_AUTO_TEST_CASE(ressol_runtime_315_bit_tests) {
    using T = number<cpp_int_modular_backend<315>>;
    BOOST_CHECK_EQUAL(
        ressol(T(1024u), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 32u);
    BOOST_CHECK_EQUAL(
        ressol(T(16u), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 4u);
   BOOST_CHECK_EQUAL(
        ressol(T(120846049u), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));
   BOOST_CHECK_EQUAL(
      ressol(T(1025), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
      T("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565985187"));
}

BOOST_AUTO_TEST_CASE(ressol_runtime_18_bit_tests) {
    using T = number<cpp_int_modular_backend<18>>;
 
    BOOST_CHECK_EQUAL(ressol(T(1024u), T(174763u)), 174731u);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_7_bit_tests) {
    using T = number<cpp_int_modular_backend<7>>;
 
    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(64), T(85)), 0u);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_8_bit_tests) {
    using T = number<cpp_int_modular_backend<8>>;
 
    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(181), T(217)), 0);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_16_bit_tests) {
    using T = number<cpp_int_modular_backend<16>>;
 
    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(4225), T(33153)), 0);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_15_bit_tests) {
    using T = number<cpp_int_modular_backend<15>>;
 
    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(2048), T(31417)), 0);
}

BOOST_AUTO_TEST_CASE(ressol_runtime_13_bit_tests) {
    using T = number<cpp_int_modular_backend<13>>;
 
    // When there is no square root, we return 0 now, not -1. This will change when proper error management is introduced.
    BOOST_CHECK_EQUAL(ressol(T(2), T(4369)), 0);
}

BOOST_AUTO_TEST_SUITE_END()  // ressol_runtime_tests

//constexpr bool test_static() {
//    constexpr auto a1 = 0x5_cppui_modular4;
//    constexpr auto p1 = 0xb_cppui_modular4;
//    constexpr auto res1 = 0x4_cppui_modular4;
//    static_assert(ressol(a1, p1) == res1, "ressol error");
//
//    constexpr auto a2 = 0x5_cppui_modular521;
//    constexpr auto p2 =
//        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui_modular521;
//    constexpr auto res2 =
//        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_cppui_modular521;
//    static_assert(ressol(a2, p2) == res2, "ressol error");
//
//    constexpr auto a3 = 0x4_cppui_modular521;
//    constexpr auto p3 =
//        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppui_modular521;
//    static_assert(ressol(a3, p3) == -1, "ressol error");
//
//    constexpr auto a4 = 0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_cppui_modular224;
//    constexpr auto p4 = 0xffffffffffffffffffffffffffffffff000000000000000000000001_cppui_modular224;
//    constexpr auto res4 = 0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_cppui_modular224;
//    static_assert(ressol(a4, p4) == res4, "ressol error");
//
//    constexpr auto a5 = 0x40_cppui_modular7;
//    constexpr auto p5 = 0x55_cppui_modular7;
//    static_assert(ressol(a5, p5) == -1, "ressol error");
//
//    constexpr auto a6 = 0xb5_cppui_modular8;
//    constexpr auto p6 = 0xd9_cppui_modular8;
//    static_assert(ressol(a6, p6) == -1, "ressol error");
//
//    constexpr auto a7 = 0x1081_cppui_modular16;
//    constexpr auto p7 = 0x8181_cppui_modular16;
//    static_assert(ressol(a7, p7) == -1, "ressol error");
//
//    constexpr auto a8 = 0x800_cppui_modular15;
//    constexpr auto p8 = 0x7ab9_cppui_modular15;
//    static_assert(ressol(a8, p8) == -1, "ressol error");
//
//    constexpr auto a9 = 0x2_cppui_modular13;
//    constexpr auto p9 = 0x1111_cppui_modular13;
//    static_assert(ressol(a9, p9) == -1, "ressol error");
//
//    constexpr auto a10 = 0x400_cppui_modular315;
//    constexpr auto p10 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315;
//    constexpr auto res10 = 0x20_cppui_modular315;
//    static_assert(ressol(a10, p10) == res10, "ressol error");
//
//    constexpr auto a11 = 0x400_cppui_modular18;
//    constexpr auto p11 = 0x2aaab_cppui_modular18;
//    constexpr auto res11 = 0x2aa8b_cppui_modular18;
//    static_assert(ressol(a11, p11) == res11, "ressol error");
//
//    constexpr auto a12 = 0x401_cppui_modular315;
//    constexpr auto p12 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315;
//    constexpr auto res12 = 0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_cppui_modular315;
//    static_assert(ressol(a12, p12) == res12, "ressol error");
//
//    constexpr auto a13 = 0x10_cppui_modular315;
//    constexpr auto p13 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315;
//    constexpr auto res13 = 0x4_cppui_modular315;
//    static_assert(ressol(a13, p13) == res13, "ressol error");
//
//    constexpr auto a14 = 0x733f6e1_cppui_modular315;
//    constexpr auto p14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315;
//    constexpr auto res14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_cppui_modular315;
//    static_assert(ressol(a14, p14) == res14, "ressol error");
//
//    return true;
//}

//constexpr bool test_backend_static() {
//    using cpp521 = backends::cpp_int_modular_backend<521>;
//    using cpp315 = backends::cpp_int_modular_backend<315>;
//    using cpp224 = backends::cpp_int_modular_backend<224>;
//    using cpp18 = backends::cpp_int_modular_backend<18>;
//    using cpp16 = backends::cpp_int_modular_backend<16>;
//    using cpp15 = backends::cpp_int_modular_backend<15>;
//    using cpp13 = backends::cpp_int_modular_backend<13>;
//    using cpp8 = backends::cpp_int_modular_backend<8>;
//    using cpp7 = backends::cpp_int_modular_backend<7>;
//    using cpp4 = backends::cpp_int_modular_backend<4>;
//
//    using modular_adaptor_type_4 = backends::modular_adaptor<cpp4, backends::modular_params_rt<cpp4>>;
//    constexpr auto a1_m =
//        number<modular_adaptor_type_4>(modular_adaptor_type_4(0x5_cppui_modular4, 0xb_cppui_modular4));
//    constexpr auto res1 = 0x4_cppui_modular4;
//    static_assert(ressol(a1_m).template convert_to<number<cpp4>>() == res1, "ressol error");
//
//    using modular_adaptor_type_521 = backends::modular_adaptor<cpp521, backends::modular_params_rt<cpp521>>;
//    constexpr auto a2_m = number<modular_adaptor_type_521>(modular_adaptor_type_521(
//        0x5_cppui_modular521,
//        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui_modular521));
//    constexpr auto res2 =
//        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_cppui_modular521;
//    static_assert(ressol(a2_m).template convert_to<number<cpp521>>() == res2, "ressol error");
//
//    constexpr auto a3_m = number<modular_adaptor_type_521>(modular_adaptor_type_521(
//        0x4_cppui_modular521,
//        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppui_modular521));
//    constexpr auto negone_3 = number<modular_adaptor_type_521>(modular_adaptor_type_521(
//        number<cpp521>(-1),
//        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppui_modular521));
//    static_assert(ressol(a3_m) == negone_3, "ressol error");
//
//    using modular_adaptor_type_224 = backends::modular_adaptor<cpp224, backends::modular_params_rt<cpp224>>;
//    constexpr auto a4_m = number<modular_adaptor_type_224>(modular_adaptor_type_224(
//        0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_cppui_modular224,
//        0xffffffffffffffffffffffffffffffff000000000000000000000001_cppui_modular224));
//    constexpr auto res4 = 0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_cppui_modular224;
//    static_assert(ressol(a4_m).template convert_to<number<cpp224>>() == res4, "ressol error");
//
//    using modular_adaptor_type_7 = backends::modular_adaptor<cpp7, backends::modular_params_rt<cpp7>>;
//    constexpr auto a5_m = number<modular_adaptor_type_7>(modular_adaptor_type_7(0x40_cppui_modular7, 0x55_cppui_modular7));
//    constexpr auto negone_5 = number<modular_adaptor_type_7>(modular_adaptor_type_7(0, 0x55_cppui_modular7));
//    static_assert(ressol(a5_m) == negone_5, "ressol error");
//
//    using modular_adaptor_type_8 = backends::modular_adaptor<cpp8, backends::modular_params_rt<cpp8>>;
//    constexpr auto a6_m = number<modular_adaptor_type_8>(0xb5_cppui_modular8, 0xd9_cppui_modular8);
//    constexpr auto negone_6 = number<modular_adaptor_type_8>(0, 0xd9_cppui_modular8);
//    static_assert(ressol(a6_m) == negone_6, "ressol error");
//
//    constexpr auto a7_m =
//        number<backends::modular_adaptor<cpp16, backends::modular_params_rt<cpp16>>>(0x1081_cppui_modular16, 0x8181_cppui_modular16);
//    constexpr auto negone_7 =
//        number<backends::modular_adaptor<cpp16, backends::modular_params_rt<cpp16>>>(number<cpp16>(-1), 0x8181_cppui_modular16);
//    static_assert(ressol(a7_m) == negone_7, "ressol error");
//
//    constexpr auto a8_m =
//        number<backends::modular_adaptor<cpp15, backends::modular_params_rt<cpp15>>>(0x800_cppui_modular15, 0x7ab9_cppui_modular15);
//    constexpr auto negone_8 = number<backends::modular_adaptor<cpp15, backends::modular_params_rt<cpp15>>>(
//        number<cpp15>(-1), 0x7ab9_cppui_modular15);
//    static_assert(ressol(a8_m) == negone_8, "ressol error");
//
//    constexpr auto a9_m =
//        number<backends::modular_adaptor<cpp13, backends::modular_params_rt<cpp13>>>(0x2_cppui_modular13, 0x1111_cppui_modular13);
//    constexpr auto negone_9 = number<backends::modular_adaptor<cpp13, backends::modular_params_rt<cpp13>>>(
//        number<cpp13>(-1), 0x1111_cppui_modular13);
//    static_assert(ressol(a9_m) == negone_9, "ressol error");
//
//    constexpr auto a10_m = number<backends::modular_adaptor<cpp315, backends::modular_params_rt<cpp315>>>(
//        0x400_cppui_modular315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315);
//    constexpr auto res10 = 0x20_cppui_modular315;
//    static_assert(ressol(a10_m).template convert_to<number<cpp315>>() == res10, "ressol error");
//
//    constexpr auto a11_m =
//        number<backends::modular_adaptor<cpp18, backends::modular_params_rt<cpp18>>>(0x400_cppui_modular18, 0x2aaab_cppui_modular18);
//    constexpr auto res11 = 0x2aa8b_cppui_modular18;
//    static_assert(ressol(a11_m).template convert_to<number<cpp18>>() == res11, "ressol error");
//
//    constexpr auto a12_m = number<backends::modular_adaptor<cpp315, backends::modular_params_rt<cpp315>>>(
//        0x401_cppui_modular315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315);
//    constexpr auto res12 = 0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_cppui_modular315;
//    static_assert(ressol(a12_m).template convert_to<number<cpp315>>() == res12, "ressol error");
//
//    constexpr auto a13_m = number<backends::modular_adaptor<cpp315, backends::modular_params_rt<cpp315>>>(
//        0x10_cppui_modular315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315);
//    constexpr auto res13 = 0x4_cppui_modular315;
//    static_assert(ressol(a13_m).template convert_to<number<cpp315>>() == res13, "ressol error");
//
//    constexpr auto a14_m = number<backends::modular_adaptor<cpp315, backends::modular_params_rt<cpp315>>>(
//        0x733f6e1_cppui_modular315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppui_modular315);
//    constexpr auto res14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_cppui_modular315;
//    static_assert(ressol(a14_m).template convert_to<number<cpp315>>() == res14, "ressol error");
//
//    return true;
//}

