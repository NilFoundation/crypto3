//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_EXPONENTIATION_HPP
#define ALGEBRA_EXPONENTIATION_HPP

#include <cstdint>

#include <boost/multiprecision/number.hpp>

namespace nil {
    namespace algebra {

template<typename FieldT, typename PowerType>
FieldT power(const FieldT &base, const PowerType &exponent)
{	
    FieldT result = FieldT::one();
 
    bool found_one = false;

    for (long i = msb(exponent); i >= 0; --i)
    {
        if (found_one)
        {
            result = result * result;
        }

        if (bit_test(exponent, i))
        {
            found_one = true;
            result = result * base;
        }
    }

    return result;
}

}
}

#endif // EXPONENTIATION_HPP_