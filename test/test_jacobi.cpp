///////////////////////////////////////////////////////////////
//  Copyright 2020 Mikhail Komarov. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

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

#include <nil/crypto3/multiprecision/jacobi.hpp>
#include <nil/crypto3/multiprecision/cpp_int/literals.hpp>

BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256);

template<typename T>
void test() {
    using namespace nil::crypto3::multiprecision;

    BOOST_CHECK_EQUAL(jacobi(T(5), T(9)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(1), T(27)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(2), T(27)), -1);
    BOOST_CHECK_EQUAL(jacobi(T(3), T(27)), 0);
    BOOST_CHECK_EQUAL(jacobi(T(4), T(27)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(506), T(1103)), -1);

    // new tests from algebra:
    BOOST_CHECK_EQUAL(
        jacobi(T(76749407), T("21888242871839275222246405745257275088696311157297823662689037894645226208583")), -1);
    BOOST_CHECK_EQUAL(
        jacobi(T(76749407), T("52435875175126190479447740508185965837690552500527637822603658699938581184513")), -1);
    BOOST_CHECK_EQUAL(
        jacobi(
            T(76749407),
            T("18401471844947097664173251940900308709046483937867715073880837110864239498070802969129867528264353400424"
              "03298196232503709156245534219589335680638510254027764437882223571969881035804085174863110178951694406403"
              "43141708939276039764731720833213215559801639066799283898191098079351209268491644339667178604494222971572"
              "78897105437443828133160276495096341710144889141242401158886206885011341008817780140927978648973063559908"
              "13408559307626854581748371042304462382047277716284590087959373746400022332313336095224466892979000905491"
              "1540076476091045996759150349011014772948929626145183545025870323741270110314006814529932451772897")),
        -1);
}

int main() {
    using namespace nil::crypto3::multiprecision;

#if defined(TEST_CPP_INT)
    test<cpp_int>();

    constexpr auto a = 0x4931a5f_cppui256;
    constexpr auto b = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui256;
    static_assert(jacobi(a, b) == -1, "jacobi error");
#endif
#if defined(TEST_GMP)
    test<mpz_int>();
#endif
#if defined(TEST_TOMMATH)
    test<tom_int>();
#endif

    return boost::report_errors();
}
