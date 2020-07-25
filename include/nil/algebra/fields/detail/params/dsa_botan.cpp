//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_DSA_BOTAN_PARAMS_HPP
#define ALGEBRA_FIELD_DSA_BOTAN_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            struct arithmetic_params<dsa_botan<2048>> : public params<dsa_botan<2048>> {
                constexpr static const number_type euler = 0x8CD7D450F86F0AD94EEE4CE469A8756D1EBD1058241943EAFFB0B354585E924D_cppui256;
            };

            struct arithmetic_params<dsa_botan<3072>> : public params<dsa_botan<3072>> {
                constexpr static const number_type euler = 0xB3EBD364EC69EF8CF3BAF643B75734B16339B2E49E5CDE1B59C1E9FB40EE0C5B_cppui256;
            };

        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELD_DSA_BOTAN_PARAMS_HPP
