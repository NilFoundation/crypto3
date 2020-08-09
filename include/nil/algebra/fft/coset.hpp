//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FFT_COSET_HPP
#define ALGEBRA_FFT_COSET_HPP

#include <vector>

namespace nil {
    namespace algebra {
        /**
         * Translate the vector a to a coset defined by g.
         */
        template<typename FieldType>
        void multiply_by_coset(std::vector<FieldType> &a, const FieldType &g) {
            FieldType u = g;
            for (size_t i = 1; i < a.size(); ++i) {
                a[i] *= u;
                u *= g;
            }
        }
    }    // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_COSET_HPP
