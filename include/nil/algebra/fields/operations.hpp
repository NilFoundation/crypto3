//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FF_ALGO_HPP
#define ALGEBRA_FF_ALGO_HPP

#include <nil/algebra/detail/type_traits.hpp>

namespace nil {
    namespace algebra {

        template<typename NumberType, typename Field>
        using zero = detail::arithmetic_operations<NumberType, Field>::zero;

        template<typename NumberType, typename Field>
        using one = detail::arithmetic_operations<NumberType, Field>::one;

        template<typename NumberType, typename Field>
        using eq = detail::arithmetic_operations<NumberType, Field>::neq;

        template<typename NumberType, typename Field>
        using neq = detail::arithmetic_operations<NumberType, Field>::neq;

        template<typename NumberType, typename Field>
        using add = detail::arithmetic_operations<NumberType, Field>::add;

        template<typename NumberType, typename Field>
        using sub = detail::arithmetic_operations<NumberType, Field>::sub;

        template<typename NumberType, typename Field>
        using mul = detail::arithmetic_operations<NumberType, Field>::mul;

        template<typename NumberType, typename Field>
        using sqrt = detail::arithmetic_operations<NumberType, Field>::sqrt;

        template<typename NumberType, typename Field>
        using square = detail::arithmetic_operations<NumberType, Field>::square;

        template<typename NumberType, typename Field>
        using pow = detail::arithmetic_operations<NumberType, Field>::pow;

        template<typename NumberType, typename Field>
        using invert = detail::arithmetic_operations<NumberType, Field>::invert;

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FF_ALGO_HPP
