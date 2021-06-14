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

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/dsa_jce/base_field.hpp>
#include <nil/crypto3/algebra/fields/dsa_jce/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<std::size_t Version>
                struct arithmetic_params<dsa_jce_base_field<Version>>
                    : public params<dsa_jce_base_field<Version>> {
                private:
                    typedef params<dsa_jce_base_field<Version>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type mul_generator =
                        0x469603512E30278CD3947595DB22EEC9826A6322ADC97344F41D740C325724C8F9EFBAA7D4D803FF8C609DCD100EBC5BDFCFAD7C6A425FAEA786EA2050EBE98351EA1FDA1FDF24D6947AA6B9AA23766953802F4D7D4A8ECBA06D19768A2491FFB16D0EF9C43A99B5F71672FF6F0A24B444D0736D04D38A1A1322DAF6CDD88C9D_cppui1024;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x9760508F15230BCCB292B982A2EB840BF0581CF5_cppui160;
                };

                template<std::size_t Version>
                constexpr typename arithmetic_params<dsa_jce_base_field<Version>>::modulus_type const
                    arithmetic_params<dsa_jce_base_field<Version>>::group_order;

                template<std::size_t Version>
                constexpr typename arithmetic_params<dsa_jce_base_field<Version>>::modulus_type const
                    arithmetic_params<dsa_jce_base_field<Version>>::mul_generator;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_DSA_JCE_ARITHMETIC_PARAMS_HPP
