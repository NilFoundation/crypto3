//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_MODP_SRP_PARAMS_HPP
#define ALGEBRA_FIELD_MODP_SRP_PARAMS_HPP

#include <nil/algebra/fields/detail/params.hpp>

namespace nil {
    namespace algebra {
        namespace detail {

            template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
            struct arithmetic_params<modp_srp<ModulusBits, GeneratorBits>> : public params<FieldType> {
                constexpr static const number_type euler = 0;
            };
        
        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELD_MODP_SRP_PARAMS_HPP
