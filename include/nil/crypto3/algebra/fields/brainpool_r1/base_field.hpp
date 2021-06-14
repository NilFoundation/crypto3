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

#ifndef CRYPTO3_ALGEBRA_FIELDS_BRAINPOOL_R1_BASE_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_BRAINPOOL_R1_BASE_FIELD_HPP

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                /*!
                 * @brief IETF IPsec groups
                 * @tparam Version
                 */
                template<std::size_t Version>
                struct brainpool_r1_base_field;

                template<>
                struct brainpool_r1_base_field<160> : public field<160> {
                    typedef field<160> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const std::size_t number_bits = policy_type::number_bits;
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type modulus = 0xE95E4A5F737059DC60DFC7AD95B3D8139515620F_cppui160;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<160>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<192> : public field<192> {
                    typedef field<192> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xC302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297_cppui192;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<192>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<224> : public field<224> {
                    typedef field<224> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xD7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF_cppui224;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<224>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<256> : public field<256> {
                    typedef field<256> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377_cppui256;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<256>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<320> : public field<320> {
                    typedef field<320> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xD35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27_cppui320;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<320>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<384> : public field<384> {
                    typedef field<384> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53_cppui384;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<384>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                template<>
                struct brainpool_r1_base_field<512> : public field<512> {
                    typedef field<512> policy_type;

                    constexpr static const std::size_t modulus_bits = policy_type::modulus_bits;
                    typedef typename policy_type::modulus_type modulus_type;

                    typedef typename policy_type::extended_modulus_type extended_modulus_type;

                    constexpr static const modulus_type modulus =
                        0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3_cppui512;

                    typedef typename detail::element_fp<params<brainpool_r1_base_field<512>>> value_type;

                    constexpr static const std::size_t value_bits = modulus_bits;
                    constexpr static const std::size_t arity = 1;
                };

                constexpr
                    typename brainpool_r1_base_field<160>::modulus_type const brainpool_r1_base_field<160>::modulus;
                constexpr
                    typename brainpool_r1_base_field<192>::modulus_type const brainpool_r1_base_field<192>::modulus;
                constexpr
                    typename brainpool_r1_base_field<224>::modulus_type const brainpool_r1_base_field<224>::modulus;
                constexpr
                    typename brainpool_r1_base_field<256>::modulus_type const brainpool_r1_base_field<256>::modulus;
                constexpr
                    typename brainpool_r1_base_field<320>::modulus_type const brainpool_r1_base_field<320>::modulus;
                constexpr
                    typename brainpool_r1_base_field<384>::modulus_type const brainpool_r1_base_field<384>::modulus;
                constexpr
                    typename brainpool_r1_base_field<512>::modulus_type const brainpool_r1_base_field<512>::modulus;

                template<std::size_t Version = 160>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 192>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 224>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 256>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 320>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 384>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 512>
                using brainpool_r1_fq = brainpool_r1_base_field<Version>;

                template<std::size_t Version = 160>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 192>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 224>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 256>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 320>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 384>
                using brainpool_r1 = brainpool_r1_base_field<Version>;
                template<std::size_t Version = 512>
                using brainpool_r1 = brainpool_r1_base_field<Version>;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_BRAINPOOL_R1_BASE_FIELD_HPP
