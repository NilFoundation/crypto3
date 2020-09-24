//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_PARAMS_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<typename FieldType>
                struct params {
                    typedef FieldType field_type;
                    typedef typename field_type::number_type number_type;

                    constexpr static const std::size_t modulus_bits = field_type::modulus_bits;
                    typedef typename field_type::modulus_type modulus_type;

                    typedef typename field_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus = field_type::modulus;

                    constexpr static const std::size_t generator_bits = field_type::generator_bits;
                    typedef typename field_type::generator_type generator_type;

                    constexpr static const generator_type mul_generator = field_type::mul_generator;
                };

                template<typename FieldType>
                constexpr typename params<FieldType>::modulus_type const params<FieldType>::modulus;

                template<typename FieldType>
                constexpr typename params<FieldType>::generator_type const params<FieldType>::mul_generator;

                template<typename FieldType>
                constexpr typename std::size_t const params<FieldType>::modulus_bits;

                template<typename FieldType>
                constexpr typename std::size_t const params<FieldType>::generator_bits;

                template<typename FieldType>
                struct arithmetic_params;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PARAMS_HPP
