///////////////////////////////////////////////////////////////
//  Copyright 2012 John Maddock. Distributed under the Boost
//  Software License, Version 1.0. (See accompanying file
//  LICENSE_1_0.txt or copy at https://www.boost.org/LICENSE_1_0.txt

#include <nil/crypto3/multiprecision/cpp_int_modular.hpp>

#include "test_arithmetic.hpp"

template<unsigned Bits, boost::multiprecision::expression_template_option ExpressionTemplates>
struct is_twos_complement_integer<boost::multiprecision::number<
    boost::multiprecision::cpp_int_modular_backend<Bits>,
    ExpressionTemplates>> : public std::integral_constant<bool, false> { };

template<>
struct related_type<boost::multiprecision::cpp_int_modular> {
    typedef boost::multiprecision::int256_t type;
};
template<unsigned Bits, boost::multiprecision::expression_template_option ET>
struct related_type<boost::multiprecision::number<
    boost::multiprecision::cpp_int_modular_backend<Bits>, ET>> {
    typedef boost::multiprecision::number<
        boost::multiprecision::cpp_int_modular_backend<Bits / 2>, ET>
        type;
};

int main() {
    test<boost::multiprecision::cpp_int_modular>();
    return boost::report_errors();
}
