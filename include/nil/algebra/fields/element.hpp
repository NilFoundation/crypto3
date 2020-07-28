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
#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            template<typename Field, typename NumberType>
            using element = std::array<NumberType, basic_params<Field>::arity>;

            template<typename NumberType>
            using element = std::array<NumberType, basic_params<Field>::arity>;
        }
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_POINT_HPP
