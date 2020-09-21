//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FFT_COSET_HPP
#define CRYPTO3_ALGEBRA_FFT_COSET_HPP

#include <vector>

namespace nil { namespace crypto3 { namespace algebra {
        /**
         * Translate the vector a to a coset defined by g.
         */
        template<typename FieldValueType>
        void multiply_by_coset(std::vector<FieldValueType> &a, const FieldValueType &g) {
            FieldValueType u = g;
            for (size_t i = 1; i < a.size(); ++i) {
                a[i] *= u;
                u *= g;
            }
        }
    }    // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_COSET_HPP
