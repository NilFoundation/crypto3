//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP6_3OVER2_EXTENSION_HPP
#define ALGEBRA_FIELDS_FP6_3OVER2_EXTENSION_HPP

#include <nil/algebra/fields/detail/element/fp6_3over2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>
//#include <nil/algebra/fields/detail/params/alt_bn128/base_field.hpp>
//#include <nil/algebra/fields/detail/params/alt_bn128/scalar_field.hpp>
//#include <nil/algebra/fields/detail/params/bls12/base_field.hpp>
//#include <nil/algebra/fields/detail/params/bls12/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/bn128/base_field.hpp>
#include <nil/algebra/fields/detail/params/bn128/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/edwards/base_field.hpp>
#include <nil/algebra/fields/detail/params/edwards/scalar_field.hpp>
/*#include <nil/algebra/fields/detail/params/frp_v1/base_field.hpp>
#include <nil/algebra/fields/detail/params/frp_v1/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/gost_A/base_field.hpp>
#include <nil/algebra/fields/detail/params/gost_A/scalar_field.hpp>*/
#include <nil/algebra/fields/detail/params/mnt4/base_field.hpp>
#include <nil/algebra/fields/detail/params/mnt4/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/mnt6/base_field.hpp>
#include <nil/algebra/fields/detail/params/mnt6/scalar_field.hpp>
/*#include <nil/algebra/fields/detail/params/secp/base_field.hpp>
#include <nil/algebra/fields/detail/params/secp/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/sm2p_v1/base_field.hpp>
#include <nil/algebra/fields/detail/params/sm2p_v1/scalar_field.hpp>
#include <nil/algebra/fields/detail/params/x962_p/base_field.hpp>
#include <nil/algebra/fields/detail/params/x962_p/scalar_field.hpp>*/

namespace nil {
    namespace algebra {
        namespace fields {

            /*!
             * @brief
             * @tparam ModulusBits
             * @tparam GeneratorBits
             */
            template<typename BaseField>
            struct fp6_3over2 {
                typedef BaseField field_type;
                typedef detail::extension_params<field_type> policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                constexpr static const std::size_t number_bits = policy_type::number_bits;
                typedef typename policy_type::number_type number_type;

                constexpr static const modulus_type modulus = policy_type::modulus;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                constexpr static const generator_type mul_generator = policy_type::mul_generator;

                typedef typename detail::element_fp6_3over2<policy_type> value_type;

                constexpr static const std::size_t arity = 6;
            };

            template<typename BaseField>
            constexpr typename fp6_3over2<BaseField>::modulus_type const fp6_3over2<BaseField>::modulus;

            template<typename BaseField>
            constexpr typename fp6_3over2<BaseField>::generator_type const fp6_3over2<BaseField>::mul_generator;

            template<typename BaseField>
            constexpr typename std::size_t const fp6_3over2<BaseField>::arity;

        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP6_3OVER2_EXTENSION_HPP
