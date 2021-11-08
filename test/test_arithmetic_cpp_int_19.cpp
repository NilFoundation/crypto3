///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_int.hpp>

#include "test_arithmetic.hpp"

template<unsigned MinBits, unsigned MaxBits, nil::crypto3::multiprecision::cpp_integer_type SignType, class Allocator,
         nil::crypto3::multiprecision::expression_template_option ExpressionTemplates>
struct is_twos_complement_integer<nil::crypto3::multiprecision::number<
    nil::crypto3::multiprecision::cpp_int_backend<MinBits, MaxBits, SignType, nil::crypto3::multiprecision::checked,
                                                  Allocator>,
    ExpressionTemplates>> : public boost::mpl::false_ { };

int main() {
    test<nil::crypto3::multiprecision::number<
        nil::crypto3::multiprecision::rational_adaptor<nil::crypto3::multiprecision::int128_t::backend_type>>>();
    return boost::report_errors();
}
