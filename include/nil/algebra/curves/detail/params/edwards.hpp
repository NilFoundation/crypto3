//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_PARAMS_HPP
#define ALGEBRA_CURVES_EDWARDS_PARAMS_HPP

#include <nil/algebra/curves/edwards.hpp>

#include <nil/algebra/curves/detail/params/params.hpp>

#include <nil/algebra/fields/edwards/fq.hpp>

#include <nil/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template <std::size_t ModulusBits>
                struct pairing_params<edwards<ModulusBits>> {

                };

            }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_EDWARDS_PARAMS_HPP
