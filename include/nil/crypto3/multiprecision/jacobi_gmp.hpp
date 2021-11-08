//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Aleksei Moskvin <alalmoskvin@gmail.com>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_JACOBI_GMP_HPP
#define BOOST_MULTIPRECISION_JACOBI_GMP_HPP

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                int eval_jacobi(const gmp_int &a, const gmp_int &b) {
                    return mpz_jacobi(a.data(), b.data());
                }
            }
        }    // namespace multiprecision
    }        // namespace crypto3
}    // namespace nil

#endif    // BOOST_MULTIPRECISION_JACOBI_GMP_HPP
