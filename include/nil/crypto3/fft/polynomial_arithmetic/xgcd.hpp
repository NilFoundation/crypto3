//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef XGCD_HPP_
#define XGCD_HPP_

#include <vector>

namespace libfqfft {

    /**
     * Perform the standard Extended Euclidean Division algorithm.
     * Input: Polynomial A, Polynomial B.
     * Output: Polynomial G, Polynomial U, Polynomial V, such that G = (A * U) + (B * V).
     */
    template<typename FieldT>
    void _polynomial_xgcd(const std::vector<FieldT> &a, const std::vector<FieldT> &b, std::vector<FieldT> &g,
                          std::vector<FieldT> &u, std::vector<FieldT> &v);

}    // namespace libfqfft

#include <libfqfft/polynomial_arithmetic/xgcd.tcc>

#endif    // XGCD_HPP_
