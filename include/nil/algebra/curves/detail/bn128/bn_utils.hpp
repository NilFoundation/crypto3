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
        namespace curves {
            namespace detail {

                template<typename FieldType>
                void bn_batch_invert(std::vector<FieldType> &vec) {
                    std::vector<FieldType> prod;
                    prod.reserve(vec.size());

                    FieldType acc = 1;

                    for (auto el : vec) {
                        assert(!el.isZero());
                        prod.emplace_back(acc);
                        FieldType::mul(acc, acc, el);
                    }

                    FieldType acc_inverse = acc;
                    acc_inverse.inverse();

                    for (long i = vec.size() - 1; i >= 0; --i) {
                        const FieldType old_el = vec[i];
                        FieldType::mul(vec[i], acc_inverse, prod[i]);
                        FieldType::mul(acc_inverse, acc_inverse, old_el);
                    }
                }

            }    // namespace detail
        }        // namespace curves
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_BN_UTILS_HPP
