//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_ALGO_HPP
#define ALGEBRA_CURVES_ALGO_HPP

#include <nil/algebra/detail/type_traits.hpp>

namespace nil {
    namespace algebra {

        template<typename NumberType, typename Curve>
        using zero = basic_operations<NumberType, Curve>::zero;

        template<typename NumberType, typename Curve>
        using eq = basic_operations<NumberType, Curve>::neq;

        template<typename NumberType, typename Curve>
        using neq = basic_operations<NumberType, Curve>::neq;

        template<typename NumberType, typename Curve>
        using add = basic_operations<NumberType, Curve>::add;

        template<typename NumberType, typename Curve>
        using sub = basic_operations<NumberType, Curve>::sub;

        template<typename NumberType, typename Curve>
        using double_of = basic_operations<NumberType, Curve>::double;

        template<typename NumberType, typename Curve>
        using mul = basic_operations<NumberType, Curve>::mul;

        template<typename NumberType, typename Curve>
        using invert = basic_operations<NumberType, Curve>::invert;

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_ALGO_HPP
