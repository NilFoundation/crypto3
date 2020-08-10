//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELD_PARAMS_HPP
#define ALGEBRA_FIELD_PARAMS_HPP

#include <cstdint>

namespace nil {
    namespace algebra {
        namespace detail {

            template<typename FieldType>
            struct params {
                typedef FieldType field_type;
                typedef typename field_type::number_type number_type;

                constexpr static const std::size_t modulus_bits = field_type::modulus_bits;
                typedef typename field_type::modulus_type modulus_type;

                constexpr static const modulus_type modulus = field_type::modulus;

                constexpr static const std::size_t generator_bits = field_type::generator_bits;
                typedef typename field_type::generator_type generator_type;

                constexpr static const generator_type generator = field_type::generator;

            };

            template<typename FieldType>
            struct basic_params : public params<FieldType> {
                typedef typename params<FieldType>::number_type number_type;

                constexpr static const std::size_t arity = 1;
            };

            template<typename FieldType>
            struct arithmetic_params : public basic_params<FieldType> {
                typedef typename basic_params<FieldType>::number_type number_type;

                constexpr static const number_type q = (modulus - 1) / 2;
            };

        }    // namespace detail
    }    // namespace algebra
}    // namespace nil

#endif    // CRYPTO3_PARAMS_HPP
