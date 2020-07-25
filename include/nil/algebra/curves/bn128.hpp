//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BN128_HPP
#define ALGEBRA_PAIRING_BN128_HPP

#include <nil/algebra/curves/curbe_gfp.hpp>

namespace nil {
    namespace algebra {

        template<typename NumberType>
        using bn128 = curve_gfp<NumberType>;

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_PAIRING_BN128_HPP
