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

#if !defined(TEST_MPZ) && !defined(TEST_TOMMATH) && !defined(TEST_CPP_INT)
#define TEST_TOMMATH
#define TEST_MPZ
#define TEST_CPP_INT

#ifdef _MSC_VER
#pragma message("CAUTION!!: No backend type specified so testing everything.... this will take some time!!")
#endif
#ifdef __GNUC__
#pragma warning "CAUTION!!: No backend type specified so testing everything.... this will take some time!!"
#endif

#endif

#if defined(TEST_MPZ)
#include <boost/multiprecision/gmp.hpp>
#endif
#if defined(TEST_TOMMATH)
#include <boost/multiprecision/tommath.hpp>
#endif
#ifdef TEST_CPP_INT
#include <boost/multiprecision/cpp_int.hpp>
#endif

#include <boost/multiprecision/ressol.hpp>
#include <boost/multiprecision/cpp_int/literals.hpp>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(4);
BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(521);

using namespace boost::multiprecision;

template <typename T>
void test()
{
   using namespace boost::multiprecision;

   BOOST_CHECK_EQUAL(ressol(T(5), T(11)), 4);
   BOOST_CHECK_EQUAL(ressol(T(5), T("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")), T("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021539968609345897897688700798659762992302941280478805021587896033442584"));
   BOOST_CHECK_EQUAL(ressol(T(4), T("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057149")), -1);
   BOOST_CHECK_EQUAL(ressol(T("20749193632488214633180774027217139706413443729200940480695355894185"), T("26959946667150639794667015087019630673557916260026308143510066298881")), T("1825097171398375765346899906888660610489759292065918530856859649959"));
   BOOST_CHECK_EQUAL(ressol(T(64), T(85)), -1);
   BOOST_CHECK_EQUAL(ressol(T(181), T(217)), -1);
   BOOST_CHECK_EQUAL(ressol(T(4225), T(33153)), -1);
   BOOST_CHECK_EQUAL(ressol(T(2048), T(31417)), -1);
   BOOST_CHECK_EQUAL(ressol(T(2), T(4369)), -1);
   BOOST_CHECK_EQUAL(ressol(T(1024), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 32);
   BOOST_CHECK_EQUAL(ressol(T(1024), T(174763)), 174731);
   BOOST_CHECK_EQUAL(ressol(T(1025), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), T("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565985187"));
   BOOST_CHECK_EQUAL(ressol(T(16), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), 4);
   BOOST_CHECK_EQUAL(ressol(T(120846049), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff")), T("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));
}

template <typename T>
void test_backend()
{

   using namespace boost::multiprecision;
   number<T> res;

   number<backends::modular_adaptor<T> > modular;

   // in modular adaptor: (-1) = p - 1

   modular = number<backends::modular_adaptor<T> >(5, 11);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(4));

   modular = number<backends::modular_adaptor<T> >(5, "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int("5128001483797946816458955548662741861156429216952843873274631897232136999791540518339021539968609345897897688700798659762992302941280478805021587896033442584"));

   modular = number<backends::modular_adaptor<T> >(4, "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057149");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >("20749193632488214633180774027217139706413443729200940480695355894185", "26959946667150639794667015087019630673557916260026308143510066298881");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int("1825097171398375765346899906888660610489759292065918530856859649959"));

   modular = number<backends::modular_adaptor<T> >(64, 85);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >(181, 217);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >(4225, 33153);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >(2048, 31417);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >(2, 4369);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(-1) + cpp_int(modular.backend().mod_data().get_mod()));

   modular = number<backends::modular_adaptor<T> >(1024, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(32));

   modular = number<backends::modular_adaptor<T> >(1024, 174763);
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(174731));

   modular = number<backends::modular_adaptor<T> >(1025, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int("7195614950510915163755738138441999335431224576038191833055420996031360079131617522512565985187"));

   modular = number<backends::modular_adaptor<T> >(16, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int(4));

   modular = number<backends::modular_adaptor<T> >(120846049, "0x40000000000000000000000000000000000000000000000000000000000c100000000000000ffff");
   modular.backend().mod_data().adjust_regular(res.backend(), ressol(modular).backend().base_data());
   BOOST_CHECK_EQUAL(cpp_int(res.backend()), cpp_int("0x40000000000000000000000000000000000000000000000000000000000c100000000000000d50e"));

}

int main()
{
#ifdef TEST_CPP_INT
   test<boost::multiprecision::cpp_int>();
   test_backend<boost::multiprecision::cpp_int_backend<>>();
#endif
#ifdef TEST_MPZ
   test<boost::multiprecision::mpz_int>();
#endif
#if defined(TEST_TOMMATH)
   test<boost::multiprecision::tom_int>();
#endif

   constexpr auto a1 = 0x5_cppi521;
   constexpr auto p1 = 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppi521;
   constexpr auto res1 = 0x17e76bd20bdb7664ba9117dd46c437ac50063e33390efa159b637a043df2fbfa55e97b9f7dc55968462121ec1b7a8d686ff263d511011f1b2ee6af5fa7726b97b18_cppi521;
   static_assert(ressol(a1, p1) == res1, "ressol error");

   constexpr auto a2 = 0x5_cppi4;
   constexpr auto p2 = 0xb_cppi4;
   constexpr auto res2 = 0x4_cppi4;
   static_assert(ressol(a2, p2) == res2, "ressol error");

   constexpr auto a3 = 0x4_cppi521;
   constexpr auto p3 = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521;
   static_assert(ressol(a3, p3) == -1, "ressol error");

   constexpr auto a4_m = number<backends::modular_adaptor<backends::cpp_int_backend<4, 4>> >(0x5_cppi4, 0xb_cppi4);
   static_assert(ressol(a4_m).template convert_to<number<backends::cpp_int_backend<4, 4>>>() == res2, "ressol error");

   constexpr auto a5_m = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>> >(
       0x5_cppi521,
       0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppi521);
   static_assert(ressol(a5_m).template convert_to<number<backends::cpp_int_backend<521, 521>>>() == res1, "ressol error");

   constexpr auto a6_m = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>> >(
       0x4_cppi521,
       0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521);
   constexpr auto negone = number<backends::modular_adaptor<backends::cpp_int_backend<521, 521>> >(
       number<backends::cpp_int_backend<521, 521>>(-1),
       0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd_cppi521);
   static_assert(ressol(a6_m) == negone, "ressol error");

   return boost::report_errors();
}
