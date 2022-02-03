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

#ifndef CRYPTO3_ALGEBRA_FIELDS_PALLAS_ARITHMETIC_PARAMS_HPP
#define CRYPTO3_ALGEBRA_FIELDS_PALLAS_ARITHMETIC_PARAMS_HPP

#include <nil/crypto3/algebra/fields/params.hpp>

#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>
#include <nil/crypto3/algebra/fields/pallas/scalar_field.hpp>

#include <nil/crypto3/detail/literals.hpp>

namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {

                // template<>
                // struct arithmetic_params<pallas_base_field<255>> : public params<pallas_base_field<254>> {
                // private:
                //     typedef params<pallas_base_field<255>> policy_type;

                // public:
                //     typedef typename policy_type::modular_type modular_type;
                //     typedef typename policy_type::integral_type integral_type;

                //     constexpr static const std::size_t s = 0x20;
                //     constexpr static const integral_type root_of_unity =
                //         0x1ea14637cbe1870c65d520c6cd47d259883000713dc3c2a1adf8b071592f247a_cppui255;
                // };

                template<>
                struct arithmetic_params<pallas_scalar_field<255>> : public params<pallas_scalar_field<255>> {
                private:
                    typedef params<pallas_scalar_field<255>> policy_type;

                public:
                    typedef typename policy_type::modular_type modular_type;
                    typedef typename policy_type::integral_type integral_type;

                    constexpr static const std::size_t s = 0x20;
                    constexpr static const integral_type root_of_unity =
                        0x1ea14637cbe1870c65d520c6cd47d259883000713dc3c2a1adf8b071592f247a_cppui255;
                };

                //  constexpr std::size_t const arithmetic_params<pallas_base_field<255>>::s;
                constexpr std::size_t const arithmetic_params<pallas_scalar_field<255>>::s;

                // constexpr typename arithmetic_params<pallas_base_field<255>>::integral_type const
                // arithmetic_params<pallas_base_field<255>>::root_of_unity;
                constexpr typename arithmetic_params<pallas_scalar_field<255>>::integral_type const
                arithmetic_params<pallas_scalar_field<255>>::root_of_unity;

            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_PALLAS_ARITHMETIC_PARAMS_HPP
