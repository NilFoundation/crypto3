///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#ifdef _MSC_VER
#define _SCL_SECURE_NO_WARNINGS
#endif

#include <nil/crypto3/multiprecision/gmp.hpp>

#define NO_MIXED_OPS
#define BOOST_MP_NOT_TESTING_NUMBER

#include "test_arithmetic.hpp"
#include <boost/rational.hpp>

template<class T>
struct is_boost_rational<boost::rational<T>> : public boost::mpl::true_ { };

namespace nil {
    namespace crypto3 {
        namespace multiprecision {

            template<>
            struct number_category<boost::rational<mpz_int>> : public boost::mpl::int_<number_kind_rational> { };

        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

int main() {
    test<boost::rational<nil::crypto3::multiprecision::mpz_int>>();
    return boost::report_errors();
}
