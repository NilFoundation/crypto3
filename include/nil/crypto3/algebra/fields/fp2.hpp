//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_FIELDS_FP2_EXTENSION_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FP2_EXTENSION_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/alt_bn128/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/bls12/fp2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/bn128/fp2.hpp>
/*#include <nil/crypto3/algebra/fields/detail/extension_params/frp_v1.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/gost_A.hpp>*/
#include <nil/crypto3/algebra/fields/detail/extension_params/mnt4/fp2.hpp>
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
                 * @tparam Version
                 */
                template<typename BaseField>
                struct fp2 {
                    typedef BaseField base_field_type;
                    typedef base_field_type policy_type;
                    typedef detail::fp2_extension_params<policy_type> extension_policy;
                    typedef typename extension_policy::underlying_field_type underlying_field_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus = policy_type::modulus;

                    typedef typename detail::element_fp2<extension_policy> value_type;

                    constexpr static const std::size_t arity = 2;
                    constexpr static const std::size_t value_bits = arity * modulus_bits;
                };

                template<typename BaseField>
                constexpr typename fp2<BaseField>::modulus_type const fp2<BaseField>::modulus;

                template<typename BaseField>
                constexpr typename std::size_t const fp2<BaseField>::arity;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_FP2_EXTENSION_HPP
