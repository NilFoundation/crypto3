//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_POINT_HPP
#define ALGEBRA_FIELDS_POINT_HPP

#include <array>

namespace nil {
    namespace algebra {
        namespace fields {
            template<typename Field, typename NumberType>
            using point = std::array<NumberType, Field::arity>;
        }
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_POINT_HPP
