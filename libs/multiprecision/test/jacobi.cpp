///////////////////////////////////////////////////////////////
//  Copyright (c) 2020 Mikhail Komarov.
//  Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//  Distributed under the Boost Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#define BOOST_TEST_MODULE jacobi_multiprecision_test

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>
#include <nil/crypto3/multiprecision/cpp_int_modular/literals.hpp>

#include <nil/crypto3/multiprecision/jacobi.hpp>

template<typename T>
void test() {
    using namespace boost::multiprecision;

    BOOST_CHECK_EQUAL(jacobi(T(5u), T(9u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(1u), T(27u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(2u), T(27u)), -1);
    BOOST_CHECK_EQUAL(jacobi(T(3u), T(27u)), 0);
    BOOST_CHECK_EQUAL(jacobi(T(4u), T(27u)), 1);
    BOOST_CHECK_EQUAL(jacobi(T(506u), T(1103u)), -1);

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

BOOST_AUTO_TEST_SUITE(jacobi_tests)

BOOST_AUTO_TEST_CASE(jacobi_test) {
    using namespace boost::multiprecision;

    test<cpp_int>();

    constexpr auto a = 0x4931a5f_cppui_modular256;
    constexpr auto b = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001_cppui_modular256;
    static_assert(jacobi(a, b) == -1, "jacobi error");
}

BOOST_AUTO_TEST_SUITE_END()
