//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FP2_EXTENSION_HPP
#define ALGEBRA_FIELDS_FP2_EXTENSION_HPP

#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/extension_params/alt_bn128.hpp>
#include <nil/algebra/fields/detail/extension_params/bls12.hpp>
#include <nil/algebra/fields/detail/extension_params/bn128.hpp>
#include <nil/algebra/fields/detail/extension_params/edwards.hpp>
/*#include <nil/algebra/fields/detail/extension_params/frp_v1.hpp>
#include <nil/algebra/fields/detail/extension_params/gost_A.hpp>*/
#include <nil/algebra/fields/detail/extension_params/mnt4.hpp>
#include <nil/algebra/fields/detail/extension_params/mnt6.hpp>
/*#include <nil/algebra/fields/detail/extension_params/secp.hpp>
#include <nil/algebra/fields/detail/extension_params/sm2p_v1.hpp>
#include <nil/algebra/fields/detail/extension_params/x962_p.hpp>*/

#include <nil/algebra/fields/params.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            /*!
             * @brief
             * @tparam ModulusBits
             * @tparam GeneratorBits
             */
            template<typename BaseField>
            struct fp2 {
                typedef BaseField field_type;
                typedef field_type policy_type;

                constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                typedef typename policy_type::modulus_type modulus_type;

                typedef typename policy_type::extended_modulus_type extended_modulus_type;

                constexpr static const std::size_t number_bits = policy_type::number_bits;
                typedef typename policy_type::number_type number_type;

                constexpr static const modulus_type modulus = policy_type::modulus;

                constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                typedef typename policy_type::generator_type generator_type;

                //constexpr static const generator_type mul_generator = policy_type::mul_generator;

                typedef typename detail::element_fp2<detail::fp2_extension_params<policy_type>> value_type;

                constexpr static const std::size_t arity = 2;
            };

            template<typename BaseField>
            constexpr typename fp2<BaseField>::modulus_type const fp2<BaseField>::modulus;

            //template<typename BaseField>
            //constexpr typename fp2<BaseField>::generator_type const fp2<BaseField>::mul_generator;

            template<typename BaseField>
            constexpr typename std::size_t const fp2<BaseField>::arity;

        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP2_EXTENSION_HPP
