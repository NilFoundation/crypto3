//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020-2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_CURVES_BLS12_G2_HPP
#define CRYPTO3_ALGEBRA_CURVES_BLS12_G2_HPP

#ifndef __ZKLLVM__
#include <nil/crypto3/algebra/curves/detail/bls12/377/short_weierstrass_params.hpp>
#include <nil/crypto3/algebra/curves/detail/bls12/381/short_weierstrass_params.hpp>

#include <nil/crypto3/algebra/curves/forms.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/jacobian_with_a4_0/element_g1.hpp>
#include <nil/crypto3/algebra/curves/detail/forms/short_weierstrass/element_g1_affine.hpp>
#endif

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace curves {

                template<std::size_t Version>
                class bls12;

                namespace detail {

                    /** @brief A struct representing a group G2 of BLS12 curve.
                     *    @tparam Version version of the curve
                     *
                     */
                    template<std::size_t Version, typename Form, typename Coordinates>
                    struct bls12_g2 {
#ifdef __ZKLLVM__
                        typedef __attribute__((ext_vector_type(4)))
                        __zkllvm_field_bls12381_base value_type;

                        static_assert(Version == 381 && "zkllvm works with 381 version");

                        static value_type make_value(
                            __zkllvm_field_bls12381_base chunk_0,
                            __zkllvm_field_bls12381_base chunk_1,
                            __zkllvm_field_bls12381_base chunk_2,
                            __zkllvm_field_bls12381_base chunk_3) {
                            return {chunk_0, chunk_1, chunk_2, chunk_3};
                        }

                        static value_type one () {
                            return make_value(
                                0x24AA2B2F08F0A91260805272DC51051C6E47AD4FA403B02B4510B647AE3D1770BAC0326A805BBEFD48056C8C121BDB8_cppui378,
                                0x13E02B6052719F607DACD3A088274F65596BD0D09920B61AB5DA61BBDC7F5049334CF11213945D57E5AC7D055D042B7E_cppui381,
                                0xCE5D527727D6E118CC9CDC6DA2E351AADFD9BAA8CBDD3A76D429A695160D12C923AC9CC3BACA289E193548608B82801_cppui380,
                                0x606C4A02EA734CC32ACD2B02BC28B99CB3E287E85A763AF267492AB572E99AB3F370D275CEC1DA1AAA9075FF05F79BE_cppui379
                                );
                        }

                        static value_type zero () {
                            return make_value(
                                0,
                                0,
                                0,
                                1
                                );
                        }

#else
                        using params_type = bls12_g2_params<Version, Form>;

                        using curve_type = bls12<Version>;

                        using field_type = typename params_type::field_type;

                        constexpr static const std::size_t value_bits =
                            field_type::value_bits + 1;    ///< size of the base field in bits

                        using value_type = curve_element<params_type, Form, Coordinates>;
#endif
                    };

                }    // namespace detail
            }        // namespace curves
        }            // namespace algebra
    }                // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ALGEBRA_CURVES_BLS12_G2_HPP
