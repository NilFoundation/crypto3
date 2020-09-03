//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Pavel Kharitonov <ipavrus@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_POWER_HPP
#define ALGEBRA_FIELDS_POWER_HPP

#include <cstdint>

#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/cpp_int.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {
                template<typename FieldTypeValue, typename PowerType>
                FieldTypeValue power(const FieldTypeValue &base, const PowerType &exponent) {
                    FieldTypeValue result = FieldTypeValue::one();

                    bool found_one = false;

                    for (long i = boost::multiprecision::msb(exponent); i >= 0; --i) {
                        if (found_one) {
                            result = result.square();
                        }

                        if (boost::multiprecision::bit_test(exponent, i)) {
                            found_one = true;
                            result = result * base;
                        }
                    }

                    return result;
                }
            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_POWER_HPP