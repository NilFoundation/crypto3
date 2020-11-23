///////////////////////////////////////////////////////////////
//  Copyright 2020 Mikhail Komarov. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

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
#if defined(TEST_CPP_INT)
#include <boost/multiprecision/cpp_int.hpp>
#endif

#include <boost/multiprecision/jacobi.hpp>

template <typename T>
void test()
{
   using namespace boost::multiprecision;

   BOOST_CHECK_EQUAL(jacobi(T(5), T(9)), 1);
   BOOST_CHECK_EQUAL(jacobi(T(1), T(27)), 1);
   BOOST_CHECK_EQUAL(jacobi(T(2), T(27)), -1);
   BOOST_CHECK_EQUAL(jacobi(T(3), T(27)), 0);
   BOOST_CHECK_EQUAL(jacobi(T(4), T(27)), 1);
   BOOST_CHECK_EQUAL(jacobi(T(506), T(1103)), -1);

   //new tests from algebra:
   BOOST_CHECK_EQUAL(jacobi(T(76749407), T("21888242871839275222246405745257275088696311157297823662689037894645226208583")), -1);
   BOOST_CHECK_EQUAL(jacobi(T(76749407), T("52435875175126190479447740508185965837690552500527637822603658699938581184513")), -1);
   BOOST_CHECK_EQUAL(jacobi(T(76749407), T("18401471844947097664173251940900308709046483937867715073880837110864239498070802969129867528264353400424032981962325037091562455342195893356806385102540277644378822235719698810358040851748631101789516944064034314170893927603976473172083321321555980163906679928389819109807935120926849164433966717860449422297157278897105437443828133160276495096341710144889141242401158886206885011341008817780140927978648973063559908134085593076268545817483710423044623820472777162845900879593737464000223323133360952244668929790009054911540076476091045996759150349011014772948929626145183545025870323741270110314006814529932451772897")), -1);

}

int main()
{
   using namespace boost::multiprecision;

#if defined(TEST_CPP_INT)
   test<cpp_int>();
#endif
#if defined(TEST_MPZ)
   test<mpz_int>();
#endif
#if defined(TEST_TOMMATH)
   test<tom_int>();
#endif

   return boost::report_errors();
}
