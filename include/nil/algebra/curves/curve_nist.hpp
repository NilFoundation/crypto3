//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_NIST_HPP
#define ALGEBRA_CURVES_NIST_HPP

#include <nil/crypto3/algebra/curves/curve.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            

            template<std::size_t PSize, std::size_t WordBits>
            struct curve_nist : public curve<fp<PSize, WordBits>> {
            private:
            	typedef curve<fp<PSize, WordBits>> policy_type;
            public:
            	typedef policy_type::field_type field_type;
                typedef policy_type::number_type number_type;
            };

        }    // namespace curves
    }        // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_CURVES_NIST_HPP
