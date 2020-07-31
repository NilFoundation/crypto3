//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_BN128_FR_PARAMS_HPP
#define ALGEBRA_FIELD_BN128_FR_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct arithmetic_params<bn128_fr<ModulusBits, GeneratorBits>> : public basic_params<modp_srp<ModulusBits, GeneratorBits>> {
                constexpr static const number_type euler = 10944121435919637611123202872628637544274182200208017171849102093287904247808;
            };
        
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELD_BN128_FR_PARAMS_HPP
