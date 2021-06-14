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

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/dsa_jce/base_field.hpp>
#include <nil/crypto3/algebra/fields/dsa_jce/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                template<>
                struct arithmetic_params<dsa_botan_base_field<2048>> : public params<dsa_botan_base_field<2048>> {
                private:
                    typedef params<dsa_botan_base_field<2048>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type mul_generator =
                        0xD9F5E0761B4DBD1833D6AB1A961A0996C5F22303F72D84C140F67C431D94AB5715BEA81A0C98D39CE4BCF78D6B9EBC895D34FE89D94091D5848615EF15F5E86F11D96F6C969E203DDFA58356420A49CB444B595B901A933CFE0767B594F18A07B7F91DECDBA446B88990F78F2FF91F2FE7CD43FD2E46D18EADA1F7BB6602C617F6EF3A4B284F2FD9BA10A36042DE8FA87A2CA36597FEC81157A1485E44041DF02830111CB880BBE6ED494814886F965CDC3135F5CCF1383728BF65B806F9692C0B10D6C4C09C75A6CA3B4013CB16AB2C105F6BE23AEA9000EAB2178985F972C98057E1C86E44E7218688EA4AE0F3636DCCA745C9DCD4E6AFFB67CCBC13D6131_cppui2048;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0x8CD7D450F86F0AD94EEE4CE469A8756D1EBD1058241943EAFFB0B354585E924D_cppui256;
                };

                template<>
                struct arithmetic_params<dsa_botan_base_field<3072>> : public params<dsa_botan_base_field<3072>> {
                private:
                    typedef params<dsa_botan_base_field<3072>> policy_type;

                public:
                    typedef typename policy_type::number_type number_type;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type mul_generator =
                        0x2BED21EEF83964A230AE89BBA71D9F7C39C52FC8229B4E3BC7E5944D329DA10F010EAC9E7BAF6C009FC4EB2960723E2B56DF4663E4C3AC800E9258DE2F7649D206782893F865EFCA498D2EEF30074EA5E8A7AB262712A4D94A2F3B0B9A92EE400FB38A3CC59A5DC7E436D5C004B22E35028381B51C93407EB32D4AE0FD42CB45E12D0ECEE8A26238EDE2082A7B1522113C66CEF8D745C6CF3CB945F84D2F4DE16D44A71DE198270E13F03553C88B8D323AD0B948A1BF2103A949979B6ED16FB5F3C953D95B7C8E88CA67DCF5A636FB9CA39D924215F7A884ED6C7EE3C96D8D9715427974B7C4351282E13D3773F7D28B452F10892A13C7587328DEA4827B6B369B2A8DC172ADC583F51F2A6598C5483E5BC467B02F91D059C402D18E2C2680F776AA06F49280A2C72C17CC42D5B6E740C5C4B1AB3C51C2ED092BE2A2D8B053AE5773D1425ED2B08F06E2DD50592DF1A478C15591CDFD11564FF88FF38B721D42392FDA473212DCFD8D2D88A976A00AFFE6FFFB430A359E64CA2B351CA2412394_cppui3072;

                    constexpr static const modulus_type modulus = policy_type::modulus;
                    constexpr static const modulus_type group_order =
                        0xB3EBD364EC69EF8CF3BAF643B75734B16339B2E49E5CDE1B59C1E9FB40EE0C5B_cppui256;
                };

                constexpr typename arithmetic_params<dsa_botan_base_field<2048>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<2048>>::group_order;

                constexpr typename arithmetic_params<dsa_botan_base_field<3072>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<3072>>::group_order;

                // TODO: mul_generator should be renamed
                constexpr typename arithmetic_params<dsa_botan_base_field<2048>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<2048>>::mul_generator;
                constexpr typename arithmetic_params<dsa_botan_base_field<3072>>::modulus_type const
                    arithmetic_params<dsa_botan_base_field<3072>>::mul_generator;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_ARITHMETIC_PARAMS_HPP
