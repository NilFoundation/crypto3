//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_BN128_PARAMS_HPP
#define ALGEBRA_CURVES_BN128_PARAMS_HPP

#include <nil/algebra/curves/bn128.hpp>

#include <nil/algebra/curves/detail/params/params.hpp>

#include <nil/algebra/fields/bn128/fq.hpp>

#include <nil/algebra/fields/detail/element/fp2.hpp>

namespace nil {
    namespace algebra {
        namespace curves {
            namespace detail {

                template <std::size_t ModulusBits>
                struct pairing_params<bn128<ModulusBits>> {

                    constexpr static const std::size_t g1_field_bits = ModulusBits;
                    typedef typename fields::bn128_fq<g1_field_bits, CHAR_BIT>::value_type g1_field_type_value;

                    constexpr static const std::size_t g2_field_bits = ModulusBits;
                    typedef typename fields::detail::element_fp2<fields::detail::arithmetic_params<fields::bn128_fq<g2_field_bits, CHAR_BIT>>> g2_field_type_value;
                };

            }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_BOTAN_PARAMS_HPP
