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

#ifndef CRYPTO3_ALGEBRA_FIELDS_FP12_2OVER3OVER2_EXTENSION_HPP
#define CRYPTO3_ALGEBRA_FIELDS_FP12_2OVER3OVER2_EXTENSION_HPP

#ifndef __ZKLLVM__
#include <nil/crypto3/algebra/fields/detail/element/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/alt_bn128/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/bls12/fp12_2over3over2.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/bn128/fp12_2over3over2.hpp>
/*#include <nil/crypto3/algebra/fields/detail/extension_params/frp_v1.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/gost_A.hpp>*/
/*#include <nil/crypto3/algebra/fields/detail/extension_params/secp.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/sm2p_v1.hpp>
#include <nil/crypto3/algebra/fields/detail/extension_params/x962_p.hpp>*/

#include <nil/crypto3/algebra/fields/params.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief
                 * @tparam Version
                 */
                template<typename BaseField>
                class fp12_2over3over2 {
                public:
#ifdef __ZKLLVM__
                    typedef __attribute__((ext_vector_type(12)))
                        __zkllvm_field_bls12381_base value_type;
#else
                    typedef BaseField base_field_type;
                    typedef base_field_type policy_type;
                    typedef detail::fp12_2over3over2_extension_params<policy_type> extension_policy;
                    typedef typename extension_policy::underlying_field_type underlying_field_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::integral_type integral_type;

                    typedef typename policy_type::extended_integral_type extended_integral_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::modular_type modular_type;
                    typedef typename policy_type::modular_backend modular_backend;

                    constexpr static const integral_type modulus = policy_type::modulus;

                    typedef typename detail::element_fp12_2over3over2<extension_policy> value_type;

                    constexpr static const std::size_t arity = 12;
                    constexpr static const std::size_t value_bits = arity * modulus_bits;
#endif
                };

#ifndef __ZKLLVM__
                template<typename BaseField>
                constexpr
                    typename fp12_2over3over2<BaseField>::integral_type const fp12_2over3over2<BaseField>::modulus;

                template<typename BaseField>
                constexpr typename std::size_t const fp12_2over3over2<BaseField>::arity;
#endif

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_FP12_2OVER3OVER2_EXTENSION_HPP
