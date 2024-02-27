///////////////////////////////////////////////////////////////
//  Copyright Christopher Kormanyos 2002 - 2011.
//  Copyright 2011 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt
//
// This work is based on an earlier work:
// "Algorithm 910: A Portable C++ Multiple-Precision System for Special-Function Calculations",
// in ACM TOMS, {VOL 37, ISSUE 4, (February 2011)} (C) ACM, 2011. http://doi.acm.org/10.1145/1916461.1916469

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <boost/detail/lightweight_test.hpp>
#include <boost/array.hpp>
#include "test.hpp"

#if !defined(TEST_MPF_50) && !defined(TEST_MPF) && !defined(TEST_BACKEND) && !defined(TEST_CPP_DEC_FLOAT) && \
    !defined(TEST_MPFR) && !defined(TEST_MPFR_50) && !defined(TEST_MPFI_50) && !defined(TEST_FLOAT128) &&    \
    !defined(TEST_CPP_BIN_FLOAT)
#define TEST_MPF_50
//#  define TEST_MPF
#define TEST_BACKEND
#define TEST_CPP_DEC_FLOAT
#define TEST_MPFI_50
#define TEST_FLOAT128
#define TEST_CPP_BIN_FLOAT

#ifdef _MSC_VER
#pragma message("CAUTION!!: No backend type specified so testing everything.... this will take some time!!")
#endif
#ifdef __GNUC__
#pragma warning "CAUTION!!: No backend type specified so testing everything.... this will take some time!!"
#endif

#endif

#if defined(TEST_MPF_50)
#include <nil/crypto3/multiprecision/gmp.hpp>
#endif
#if defined(TEST_MPFR_50)
#include <nil/crypto3/multiprecision/mpfr.hpp>
#endif
#if defined(TEST_MPFI_50)
#include <nil/crypto3/multiprecision/mpfi.hpp>
#endif
#ifdef TEST_BACKEND
#include <nil/crypto3/multiprecision/concepts/mp_number_archetypes.hpp>
#endif
#ifdef TEST_CPP_DEC_FLOAT
#include <nil/crypto3/multiprecision/cpp_dec_float.hpp>
#endif
#ifdef TEST_FLOAT128
#include <nil/crypto3/multiprecision/float128.hpp>
#endif
#ifdef TEST_CPP_BIN_FLOAT
#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>
#endif

template<class T>
void test() {
    std::cout << "Testing type: " << typeid(T).name() << std::endl;
    //
    // Test with some exact binary values as input - this tests our code
    // rather than the test data:
    //
    static const boost::array<boost::array<T, 2>, 13> exact_data = {{
        {{0.5, static_cast<T>("1."
                              "0471975511965977461542144610931676280657231331250352736583148641026054687620696662093449"
                              "4178070568932738269550442743555")}},
        {{0.25, static_cast<T>("1."
                               "318116071652817965745664254646040469846390966590714716853548517413333142662083276902268"
                               "67044304393238598144034722708676")}},
        {{0.75, static_cast<T>("0."
                               "722734247813415611178377352641333362025218486424440267626754132583707381914630264964827"
                               "610939101303690078815991333621490")}},
        {{1 - std::ldexp(1.0, -20), static_cast<T>("0."
                                                   "0013810680417624171821088384775674669404857064855342671421202511115"
                                                   "0044290934710742282266738617709904634187850607042604204")}},
        {{std::ldexp(1.0, -20), static_cast<T>("1."
                                               "57079537312058021283676140197495835299636605165647561806789944133748780"
                                               "804448843729970624018104090863783682329820313127")}},
        {{1, static_cast<T>("0")}},

        {{0, static_cast<T>("1."
                            "570796326794896619231321691639751442098584699687552910487472296153908203143104499314017412"
                            "67105853399107404325664115332")}},

        {{-0.5, static_cast<T>("2."
                               "094395102393195492308428922186335256131446266250070547316629728205210937524139332418689"
                               "88356141137865476539100885487110")}},
        {{-0.25, static_cast<T>("1."
                                "82347658193697527271697912863346241435077843278439110412139607489448326362412572172576"
                                "615489907313559616664616605521989")}},
        {{-0.75, static_cast<T>("2."
                                "41885840577637762728426603063816952217195091295066555334819045972410902437157873366320"
                                "721440301576429206927052194868516")}},
        {{-1 + std::ldexp(1.0, -20), static_cast<T>("3."
                                                    "140211585548030821280534544801935417256683692889571553832824341196"
                                                    "31596337686189120521215795593996893580620800721188061")}},
        {{-std::ldexp(1.0, -20), static_cast<T>("1."
                                                "5707972804692130256258819813045445312008033477186302029070451509703285"
                                                "9824172056132832858516107615934431126321507917538")}},
        {{-1, static_cast<T>("3."
                             "14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482"
                             "534211706798214808651328230665")}},
    }};
    unsigned max_err = 0;
    for (unsigned k = 0; k < exact_data.size(); k++) {
        T val = acos(exact_data[k][0]);
        T e = relative_error(val, exact_data[k][1]);
        unsigned err = e.template convert_to<unsigned>();
        if (err > max_err) {
            max_err = err;
        }
    }
    std::cout << "Max error was: " << max_err << std::endl;
#ifdef TEST_CPP_BIN_FLOAT
    BOOST_TEST(max_err < 320);
#else
    BOOST_TEST(max_err < 60);
#endif
    BOOST_TEST(asin(T(0)) == 0);
}

int main() {
#ifdef TEST_BACKEND
    test<
        nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::concepts::number_backend_float_architype>>();
#endif
#ifdef TEST_MPF_50
    test<nil::crypto3::multiprecision::mpf_float_50>();
    test<nil::crypto3::multiprecision::mpf_float_100>();
#endif
#ifdef TEST_MPFR_50
    test<nil::crypto3::multiprecision::mpfr_float_50>();
    test<nil::crypto3::multiprecision::mpfr_float_100>();
#endif
#ifdef TEST_MPFI_50
    test<nil::crypto3::multiprecision::mpfi_float_50>();
    test<nil::crypto3::multiprecision::mpfi_float_100>();
#endif
#ifdef TEST_CPP_DEC_FLOAT
    test<nil::crypto3::multiprecision::cpp_dec_float_50>();
    test<nil::crypto3::multiprecision::cpp_dec_float_100>();
#ifndef SLOW_COMPLER
    // Some "peculiar" digit counts which stress our code:
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<65>>>();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<64>>>();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<63>>>();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<62>>>();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<61, long long>>>();
    test<nil::crypto3::multiprecision::number<nil::crypto3::multiprecision::cpp_dec_float<60, long long>>>();
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<59, long long, std::allocator<char>>>>();
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_dec_float<58, long long, std::allocator<char>>>>();
#endif
#endif
#ifdef TEST_FLOAT128
    test<nil::crypto3::multiprecision::float128>();
#endif
#ifdef TEST_CPP_BIN_FLOAT
    test<nil::crypto3::multiprecision::cpp_bin_float_50>();
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::cpp_bin_float<35,
                                                    nil::crypto3::multiprecision::digit_base_10,
                                                    std::allocator<char>,
                                                    boost::long_long_type>>>();
#endif
    return boost::report_errors();
}
