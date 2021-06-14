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

#ifndef CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_HPP
#define CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief DSA group
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct dsa_botan : public field<Version> { };

                template<>
                struct dsa_botan<2048> : public field<2048> {
                    typedef field<2048> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus =
                        0x91C48A4FDFBCF7C02AE95E7DA126122B5DD2864F559B87E8E74A286D52F59BD1DE68DFD645D0E00C60C080031891980374EEB594A532BFD67B9A09EAC4B8663A07910E68F39465FB7040D25DF13932EBAC4347A530ECBA61C854F9B880D3C0C3660080587C45566DADE26BD5A394BE093B4C0F24B5AFFEF8EC6C5B3E57FB89025A9BC16769932131E16D3C94EFCAB18D0DF061203CC53E6103BC72D5594BFD40CA65380F44A9A851DCB075495FC033A8A58071A1BD78FE052F66555648EB4B719D2AFE8B4880F8DAD6F15818BA178F89274C870BE9B96EB08C46C40040CC2EFE1DFB1B1868DD319DE3C34A32A63AB6EB1224209A419680CC7902D1728D4DF9E1_cppui2048;

                    typedef typename detail::element_fp<params<dsa_botan<modulus_bits>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct dsa_botan<3072> : public field<3072> {
                    typedef field<3072> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    constexpr static const modulus_type modulus =
                        0xE4B50880759663585E142460CA2D9DFF132F8AE4C840DDA3A2666889124FE5638B84E8A29B7AF3FA1209BE6BFC4B5072ED3B2B7387BAF3F857F478A80228EF3600B76B3DCFB61D20D34465B2506D2CAF87DF6E7DC0CE91BD2D167A46F6ADCC31C531E4F9C7ABBDB92ADDF35B0A806C66292A5F5E17E964DD099903733AC428AB35D80EA6F685BFBA8BE4068E5418AE5ECAD9E8FF073DE2B63E4E7EAD35C8A9B70B5BD47CFB88D373B66F37931939B0AB71BD5595809086DA0155337D185A0E4FB36A519B1B6202B8591E6002449CF1CD3A66384F6D2073B1CD73BECA93BAF1E1A6117D0238F222AE1ED7FED185A890E7F67FAB8FEB9753CC134A5183DFE87AE2595F7B5C2D9FBB42249FDD59513E1D3396B3EB2FD86684F285A8448FE757A029881C40760B94EF919BDF9740C38389599EC51A6E9BB519A8E068491E9CE0A2FCFE3CB60D66CF0DFAD20A8EC684048684A61444575BD1724D7352B44A760077B3BD6BD385CE5B0A7250CC0BF768DA82923806EB9CFBB138843731B618208C759B_cppui3072;

                    typedef typename detail::element_fp<params<dsa_botan<modulus_bits>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr typename dsa_botan<2048>::modulus_type const dsa_botan<2048>::modulus;
                constexpr typename dsa_botan<3072>::modulus_type const dsa_botan<3072>::modulus;
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_DSA_BOTAN_HPP
