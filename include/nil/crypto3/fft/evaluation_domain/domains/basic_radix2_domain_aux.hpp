//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BASIC_RADIX2_DOMAIN_AUX_HPP_
#define BASIC_RADIX2_DOMAIN_AUX_HPP_

#include <vector>

namespace libfqfft {

    /**
     * Compute the radix-2 FFT of the vector a over the set S={omega^{0},...,omega^{m-1}}.
     */
    template<typename FieldT>
    void _basic_radix2_FFT(std::vector<FieldT> &a, const FieldT &omega);

    /**
     * A multi-thread version of _basic_radix2_FFT.
     */
    template<typename FieldT>
    void _parallel_basic_radix2_FFT(std::vector<FieldT> &a, const FieldT &omega);

    /**
     * Translate the vector a to a coset defined by g.
     */
    template<typename FieldT>
    void _multiply_by_coset(std::vector<FieldT> &a, const FieldT &g);

    /**
     * Compute the m Lagrange coefficients, relative to the set S={omega^{0},...,omega^{m-1}}, at the field element t.
     */
    template<typename FieldT>
    std::vector<FieldT> _basic_radix2_evaluate_all_lagrange_polynomials(const size_t m, const FieldT &t);

}    // namespace libfqfft

#include <libfqfft/evaluation_domain/domains/basic_radix2_domain_aux.tcc>

#endif    // BASIC_RADIX2_DOMAIN_AUX_HPP_
