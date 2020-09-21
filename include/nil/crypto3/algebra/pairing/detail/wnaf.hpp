//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_PAIRING_WNAF_HPP
#define CRYPTO3_ALGEBRA_PAIRING_WNAF_HPP

#include <vector>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace pairing {
                namespace detail {

                    using namespace nil::crypto3::algebra;

                    template<typename NumberType>
                    std::vector<long> find_wnaf(const size_t window_size, const NumberType &scalar) {
                        std::vector<long> res(128);

                        return res;
                    }

                }    // namespace detail
            }        // namespace pairing
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_PAIRING_WNAF_HPP