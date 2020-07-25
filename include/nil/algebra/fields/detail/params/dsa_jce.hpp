//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_DSA_JCE_PARAMS_HPP
#define ALGEBRA_FIELD_DSA_JCE_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            struct arithmetic_params<dsa_jce<1024>> : public params<dsa_jce<1024>> {
                constexpr static const number_type euler = 0x9760508F15230BCCB292B982A2EB840BF0581CF5_cppui160;
            };

        }    // namespace detail
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELD_DSA_JCE_PARAMS_HPP
