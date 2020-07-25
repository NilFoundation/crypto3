//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_BN_UTILS_HPP
#define ALGEBRA_FF_BN_UTILS_HPP

#include <vector>

namespace nil {
    namespace algebra {

        template<typename FieldT>
        void bn_batch_invert(std::vector<FieldT> &vec) {
            std::vector<FieldT> prod;
            prod.reserve(vec.size());

            FieldT acc = 1;

            for (auto el : vec) {
                assert(!el.isZero());
                prod.emplace_back(acc);
                FieldT::mul(acc, acc, el);
            }

            FieldT acc_inverse = acc;
            acc_inverse.inverse();

            for (long i = vec.size() - 1; i >= 0; --i) {
                const FieldT old_el = vec[i];
                FieldT::mul(vec[i], acc_inverse, prod[i]);
                FieldT::mul(acc_inverse, acc_inverse, old_el);
            }
        }

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_BN_UTILS_HPP
