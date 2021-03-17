//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2018-2020 Pavel Kharitonov <ipavrus@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include "test.hpp"

#if !defined(TEST_GMP) && !defined(TEST_TOMMATH) && !defined(TEST_CPP_INT)
#define TEST_TOMMATH
#define TEST_GMP
#define TEST_CPP_INT

#ifdef _MSC_VER
#pragma message("CAUTION!!: No backend type specified so testing everything.... this will take some time!!")
#endif
#ifdef __GNUC__
#pragma warning "CAUTION!!: No backend type specified so testing everything.... this will take some time!!"
#endif

#endif

#if defined(TEST_GMP)
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#if defined(TEST_TOMMATH)
#include <nil/crypto3/multiprecision/tommath.hpp>
#endif
#if defined(TEST_CPP_INT)
#include <nil/crypto3/multiprecision/cpp_int.hpp>
#endif

#include <nil/crypto3/multiprecision/ressol.hpp>
#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>

#if defined(TEST_CPP_INT)

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(4);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(7);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(8);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(13);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(15);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(16);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(18);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(224);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(315);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521);

#endif

using namespace nil::crypto3::multiprecision;

template<typename T>
void test() {
    using namespace nil::crypto3::multiprecision;

    BOOST_CHECK_EQUAL(ressol(T(5), T(11)), 4);
    BOOST_CHECK_EQUAL(ressol(T(5),
                             T("686479766013060971498190079908139321726943530014330540939446345918554318339765605212255"
                               "9640661454554977296311391480858037121987999716643812574028291115057151")),
                      T("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021539968"
                        "609345897897688700798659762992302941280478805021587896033442584"));
    BOOST_CHECK_EQUAL(ressol(T(4),
                             T("686479766013060971498190079908139321726943530014330540939446345918554318339765605212255"
                               "9640661454554977296311391480858037121987999716643812574028291115057149")),
                      -1);
    BOOST_CHECK_EQUAL(ressol(T("20749193632488214633180774027217139706413443729200940480695355894185"),
                             T("26959946667150639794667015087019630673557916260026308143510066298881")),
                      T("1825097171398375765346899906888660610489759292065918530856859649959"));
    BOOST_CHECK_EQUAL(ressol(T(64), T(85)), -1);
    BOOST_CHECK_EQUAL(ressol(T(181), T(217)), -1);
    BOOST_CHECK_EQUAL(ressol(T(4225), T(33153)), -1);
    BOOST_CHECK_EQUAL(ressol(T(2048), T(31417)), -1);
    BOOST_CHECK_EQUAL(ressol(T(2), T(4369)), -1);
    BOOST_CHECK_EQUAL(
        ressol(T(1024), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 32);
    BOOST_CHECK_EQUAL(ressol(T(1024), T(174763)), 174731);
    BOOST_CHECK_EQUAL(
        ressol(T(1025), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        T("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565985187"));
    BOOST_CHECK_EQUAL(
        ressol(T(16), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 4);
    BOOST_CHECK_EQUAL(
        ressol(T(120846049), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")),
        T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));
}

template<typename T>
void test_backend() {

    using namespace nil::crypto3::multiprecision;
    number<T> res;

    number<backends::modular_adaptor<T>> modular;

    // in modular adaptor: (-1) = p - 1

    modular = number<backends::modular_adaptor<T>>(5, 11);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(4));

    modular = number<backends::modular_adaptor<T>>(
        5,
        "68647976601306097149819007990813932172694353001433054093944634591855431833976560521225596406614545549772963113"
        "91480858037121987999716643812574028291115057151");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()),
                      cpp_int("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021"
                              "539968609345897897688700798659762992302941280478805021587896033442584"));

    modular = number<backends::modular_adaptor<T>>(
        4,
        "68647976601306097149819007990813932172694353001433054093944634591855431833976560521225596406614545549772963113"
        "91480858037121987999716643812574028291115057149");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular =
        number<backends::modular_adaptor<T>>("20749193632488214633180774027217139706413443729200940480695355894185",
                                             "26959946667150639794667015087019630673557916260026308143510066298881");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()),
                      cpp_int("1825097171398375765346899906888660610489759292065918530856859649959"));

    modular = number<backends::modular_adaptor<T>>(64, 85);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular = number<backends::modular_adaptor<T>>(181, 217);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular = number<backends::modular_adaptor<T>>(4225, 33153);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular = number<backends::modular_adaptor<T>>(2048, 31417);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular = number<backends::modular_adaptor<T>>(2, 4369);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

    modular = number<backends::modular_adaptor<T>>(
        1024, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(32));

    modular = number<backends::modular_adaptor<T>>(1024, 174763);
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(174731));

    modular = number<backends::modular_adaptor<T>>(
        1025, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(
        cpp_int(res.backend()),
        cpp_int("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565985187"));

    modular = number<backends::modular_adaptor<T>>(
        16, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(4));

    modular = number<backends::modular_adaptor<T>>(
        120846049, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
    modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
    BOOST_CHECK_EQUAL(cpp_int(res.backend()),
                      cpp_int("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));
}

#if defined(TEST_CPP_INT)

constexpr bool test_static() {
    constexpr auto a1 = 0x5_cppi4;
    constexpr auto p1 = 0xb_cppi4;
    constexpr auto res1 = 0x4_cppi4;
    static_assert(ressol(a1, p1) == res1, "ressol error");

    constexpr auto a2 = 0x5_cppi521;
    constexpr auto p2 =
        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppi521;
    constexpr auto res2 =
        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_cppi521;
    static_assert(ressol(a2, p2) == res2, "ressol error");

    constexpr auto a3 = 0x4_cppi521;
    constexpr auto p3 =
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521;
    static_assert(ressol(a3, p3) == -1, "ressol error");

    constexpr auto a4 = 0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_cppi224;
    constexpr auto p4 = 0xffffffffffffffffffffffffffffffff000000000000000000000001_cppi224;
    constexpr auto res4 = 0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_cppi224;
    static_assert(ressol(a4, p4) == res4, "ressol error");

    constexpr auto a5 = 0x40_cppi7;
    constexpr auto p5 = 0x55_cppi7;
    static_assert(ressol(a5, p5) == -1, "ressol error");

    constexpr auto a6 = 0xb5_cppi8;
    constexpr auto p6 = 0xd9_cppi8;
    static_assert(ressol(a6, p6) == -1, "ressol error");

    constexpr auto a7 = 0x1081_cppi16;
    constexpr auto p7 = 0x8181_cppi16;
    static_assert(ressol(a7, p7) == -1, "ressol error");

    constexpr auto a8 = 0x800_cppi15;
    constexpr auto p8 = 0x7ab9_cppi15;
    static_assert(ressol(a8, p8) == -1, "ressol error");

    constexpr auto a9 = 0x2_cppi13;
    constexpr auto p9 = 0x1111_cppi13;
    static_assert(ressol(a9, p9) == -1, "ressol error");

    constexpr auto a10 = 0x400_cppi315;
    constexpr auto p10 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315;
    constexpr auto res10 = 0x20_cppi315;
    static_assert(ressol(a10, p10) == res10, "ressol error");

    constexpr auto a11 = 0x400_cppi18;
    constexpr auto p11 = 0x2aaab_cppi18;
    constexpr auto res11 = 0x2aa8b_cppi18;
    static_assert(ressol(a11, p11) == res11, "ressol error");

    constexpr auto a12 = 0x401_cppi315;
    constexpr auto p12 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315;
    constexpr auto res12 = 0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_cppi315;
    static_assert(ressol(a12, p12) == res12, "ressol error");

    constexpr auto a13 = 0x10_cppi315;
    constexpr auto p13 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315;
    constexpr auto res13 = 0x4_cppi315;
    static_assert(ressol(a13, p13) == res13, "ressol error");

    constexpr auto a14 = 0x733f6e1_cppi315;
    constexpr auto p14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315;
    constexpr auto res14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_cppi315;
    static_assert(ressol(a14, p14) == res14, "ressol error");

    return true;
}

constexpr bool test_backend_static() {
    constexpr auto a1_m = number<backends::modular_adaptor<backends::cpp_int_backend<4, 4>>>(0x5_cppi4, 0xb_cppi4);
    constexpr auto res1 = 0x4_cppi4;
    static_assert(ressol(a1_m).template convert_to<number<backends::cpp_int_backend<4, 4>>>() == res1, "ressol error");

    constexpr auto a2_m = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>>>(
        0x5_cppi521,
        0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppi521);
    constexpr auto res2 =
        0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_cppi521;
    static_assert(ressol(a2_m).template convert_to<number<backends::cpp_int_backend<521, 521>>>() == res2,
                  "ressol error");

    constexpr auto a3_m = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>>>(
        0x4_cppi521,
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521);
    constexpr auto negone_3 = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>>>(
        number<backends::cpp_int_backend<521, 521>>(-1),
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521);
    static_assert(ressol(a3_m) == negone_3, "ressol error");

    constexpr auto a4_m = number<backends::modular_adaptor<backends::cpp_int_backend<224, 224>>>(
        0xc5067ee5d80302e0561545a8467c6d5c98bc4d37672eb301c38ce9a9_cppi224,
        0xffffffffffffffffffffffffffffffff000000000000000000000001_cppi224);
    constexpr auto res4 = 0x115490c2141baa1c2407abe908fcf3416b0cb0d290dcd3960c3ec7a7_cppi224;
    static_assert(ressol(a4_m).template convert_to<number<backends::cpp_int_backend<224, 224>>>() == res4,
                  "ressol error");

    constexpr auto a5_m = number<backends::modular_adaptor<backends::cpp_int_backend<7, 7>>>(0x40_cppi7, 0x55_cppi7);
    constexpr auto negone_5 = number<backends::modular_adaptor<backends::cpp_int_backend<7, 7>>>(
        number<backends::cpp_int_backend<7, 7>>(-1), 0x55_cppi7);
    static_assert(ressol(a5_m) == negone_5, "ressol error");

    constexpr auto a6_m = number<backends::modular_adaptor<backends::cpp_int_backend<8, 8>>>(0xb5_cppi8, 0xd9_cppi8);
    constexpr auto negone_6 = number<backends::modular_adaptor<backends::cpp_int_backend<8, 8>>>(
        number<backends::cpp_int_backend<8, 8>>(-1), 0xd9_cppi8);
    static_assert(ressol(a6_m) == negone_6, "ressol error");

    constexpr auto a7_m =
        number<backends::modular_adaptor<backends::cpp_int_backend<16, 16>>>(0x1081_cppi16, 0x8181_cppi16);
    constexpr auto negone_7 = number<backends::modular_adaptor<backends::cpp_int_backend<16, 16>>>(
        number<backends::cpp_int_backend<16, 16>>(-1), 0x8181_cppi16);
    static_assert(ressol(a7_m) == negone_7, "ressol error");

    constexpr auto a8_m =
        number<backends::modular_adaptor<backends::cpp_int_backend<15, 15>>>(0x800_cppi15, 0x7ab9_cppi15);
    constexpr auto negone_8 = number<backends::modular_adaptor<backends::cpp_int_backend<15, 15>>>(
        number<backends::cpp_int_backend<15, 15>>(-1), 0x7ab9_cppi15);
    static_assert(ressol(a8_m) == negone_8, "ressol error");

    constexpr auto a9_m =
        number<backends::modular_adaptor<backends::cpp_int_backend<13, 13>>>(0x2_cppi13, 0x1111_cppi13);
    constexpr auto negone_9 = number<backends::modular_adaptor<backends::cpp_int_backend<13, 13>>>(
        number<backends::cpp_int_backend<13, 13>>(-1), 0x1111_cppi13);
    static_assert(ressol(a9_m) == negone_9, "ressol error");

    constexpr auto a10_m = number<backends::modular_adaptor<backends::cpp_int_backend<315, 315>>>(
        0x400_cppi315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315);
    constexpr auto res10 = 0x20_cppi315;
    static_assert(ressol(a10_m).template convert_to<number<backends::cpp_int_backend<315, 315>>>() == res10,
                  "ressol error");

    constexpr auto a11_m =
        number<backends::modular_adaptor<backends::cpp_int_backend<18, 18>>>(0x400_cppi18, 0x2aaab_cppi18);
    constexpr auto res11 = 0x2aa8b_cppi18;
    static_assert(ressol(a11_m).template convert_to<number<backends::cpp_int_backend<18, 18>>>() == res11,
                  "ressol error");

    constexpr auto a12_m = number<backends::modular_adaptor<backends::cpp_int_backend<315, 315>>>(
        0x401_cppi315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315);
    constexpr auto res12 = 0xdcc6506af06fe9e142cacb7b5ff56c1864fe7a0b2f7fb10739990aed564e07beb533b5edd95fa3_cppi315;
    static_assert(ressol(a12_m).template convert_to<number<backends::cpp_int_backend<315, 315>>>() == res12,
                  "ressol error");

    constexpr auto a13_m = number<backends::modular_adaptor<backends::cpp_int_backend<315, 315>>>(
        0x10_cppi315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315);
    constexpr auto res13 = 0x4_cppi315;
    static_assert(ressol(a13_m).template convert_to<number<backends::cpp_int_backend<315, 315>>>() == res13,
                  "ressol error");

    constexpr auto a14_m = number<backends::modular_adaptor<backends::cpp_int_backend<315, 315>>>(
        0x733f6e1_cppi315, 0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff_cppi315);
    constexpr auto res14 = 0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e_cppi315;
    static_assert(ressol(a14_m).template convert_to<number<backends::cpp_int_backend<315, 315>>>() == res14,
                  "ressol error");

    return true;
}

#endif

int main() {
#if defined(TEST_CPP_INT)
    test<nil::crypto3::multiprecision::cpp_int>();
    test_backend<nil::crypto3::multiprecision::cpp_int_backend<>>();
    constexpr bool res1 = test_static();
    constexpr bool res2 = test_backend_static();
#endif
#ifdef TEST_GMP
    test<nil::crypto3::multiprecision::mpz_int>();
#endif
#if defined(TEST_TOMMATH)
    test<nil::crypto3::multiprecision::tom_int>();
#endif

    return boost::report_errors();
}
