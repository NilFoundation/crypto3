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

#ifndef CRYPTO3_ALGEBRA_CURVES_VESTA_PARAMS_HPP
#define CRYPTO3_ALGEBRA_CURVES_VESTA_PARAMS_HPP

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/vesta/types.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {
                namespace detail {
                 

                    /**
                     * @brief https://zips.z.cash/protocol/protocol.pdf#pallasandvesta
                     */
                    template<>
                    class vesta_params<forms::short_weierstrass> {
                    public:
                        using base_field_type = typename vesta_types::base_field_type;
                        using scalar_field_type = typename vesta_types::scalar_field_type;
#ifdef __ZKLLVM__
#else
                        constexpr static typename vesta_types::integral_type a = typename vesta_types::integral_type(0)  ; ///< coefficient
                                                                                                             ///< Short
                                                                                                             ///< Weierstrass
                                                                                                             ///< curves
                                                                                                             ///< y^2=x^3+a*x+b
                        constexpr static typename vesta_types::integral_type b = typename vesta_types::integral_type(5) ;  ///< coefficient
                                                                                                             ///<  of
                                                                                                             ///< Short
                                                                                                             ///< Weierstrass
                                                                                                             ///< curves
                                                                                                             ///< y^2=x^3+a*x+b
#endif
                    };

                    template<>
                    class vesta_g1_params<forms::short_weierstrass>
                        : public vesta_params<forms::short_weierstrass> {
                    public:
                        using field_type = typename vesta_types::g1_field_type;

                        template<typename Coordinates>
                        using group_type = vesta_types::g1_type<forms::short_weierstrass, Coordinates>;
#ifdef __ZKLLVM__
#else
                        constexpr static std::array<typename field_type::value_type,2> zero_fill = {
                            field_type::value_type::zero(), field_type::value_type::one()};

                        constexpr static std::array<typename field_type::value_type, 2> one_fill = {
                            typename field_type::value_type(-1),
                                //0x7706c37b5a84128a3884a5d71811f1b55da3230ffb17a8ab0b32e48d31a6685c_cppui255),
                            typename field_type::value_type(2)};
                                //0x0f60480c7a5c0e1140340adc79d6a2bf0cb57ad049d025dc38d80c77985f0329_cppui255)};
#endif
                    };

#ifdef __ZKLLVM__
#else
                    constexpr typename vesta_types::integral_type vesta_params<forms::short_weierstrass>::a;
                    constexpr typename vesta_types::integral_type vesta_params<forms::short_weierstrass>::b;

                    constexpr std::array<typename vesta_g1_params<forms::short_weierstrass>::field_type::value_type, 2>
                        vesta_g1_params<forms::short_weierstrass>::zero_fill;
                    constexpr std::array<typename vesta_g1_params<forms::short_weierstrass>::field_type::value_type, 2>
                        vesta_g1_params<forms::short_weierstrass>::one_fill;
#endif

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_CURVES_VESTA_PARAMS_HPP
