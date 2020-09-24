//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_FP3_EXTENSION_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FP3_EXTENSION_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp3.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/edwards/fp3.hpp>
/*#include <nil/crypto3/algebra/fields/detail/extension_params/frp_v1.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/gost_A.hpp>*/
#include <nil/crypto3/algebra/fields/detail/extension_params/mnt6/fp3.hpp>
/*#include <nil/crypto3/algebra/fields/detail/extension_params/secp.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/sm2p_v1.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/x962_p.hpp>*/

#include <nil/crypto3/algebra/fields/params.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief
                 * @tparam ModulusBits
                 * @tparam GeneratorBits
                 */
                template<typename BaseField>
                struct fp3 {
                    typedef BaseField base_field_type;
                    typedef base_field_type policy_type;
                    typedef detail::fp3_extension_params<policy_type> extension_policy;
                    typedef typename extension_policy::underlying_field_type underlying_field_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    constexpr static const std::size_t generator_bits = policy_type::generator_bits;
                    typedef typename policy_type::generator_type generator_type;

                    // constexpr static const generator_type mul_generator = policy_type::mul_generator;

                    typedef typename detail::element_fp3<extension_policy> value_type;

                    constexpr static const std::size_t arity = 3;
                    constexpr static const std::size_t element_size = arity * modulus_bits;
                };

                template<typename BaseField>
                constexpr typename fp3<BaseField>::modulus_type const fp3<BaseField>::modulus;

                // template<typename BaseField>
                // constexpr typename fp3<BaseField>::generator_type const fp3<BaseField>::mul_generator;

                template<typename BaseField>
                constexpr typename std::size_t const fp3<BaseField>::arity;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FP3_EXTENSION_HPP
