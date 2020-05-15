//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef GEOMETRIC_SEQUENCE_DOMAIN_HPP
#define GEOMETRIC_SEQUENCE_DOMAIN_HPP

#include <libfqfft/evaluation_domain/evaluation_domain.hpp>

namespace libfqfft {

    template<typename FieldT>
    class geometric_sequence_domain : public evaluation_domain<FieldT> {
    public:
        bool precomputation_sentinel;
        std::vector<FieldT> geometric_sequence;
        std::vector<FieldT> geometric_triangular_sequence;
        void do_precomputation();

        geometric_sequence_domain(const size_t m);

        void FFT(std::vector<FieldT> &a);
        void iFFT(std::vector<FieldT> &a);
        void cosetFFT(std::vector<FieldT> &a, const FieldT &g);
        void icosetFFT(std::vector<FieldT> &a, const FieldT &g);
        std::vector<FieldT> evaluate_all_lagrange_polynomials(const FieldT &t);
        FieldT get_domain_element(const size_t idx);
        FieldT compute_vanishing_polynomial(const FieldT &t);
        void add_poly_Z(const FieldT &coeff, std::vector<FieldT> &H);
        void divide_by_Z_on_coset(std::vector<FieldT> &P);
    };

}    // namespace libfqfft

#include <libfqfft/evaluation_domain/domains/geometric_sequence_domain.tcc>

#endif    // GEOMETRIC_SEQUENCE_DOMAIN_HPP