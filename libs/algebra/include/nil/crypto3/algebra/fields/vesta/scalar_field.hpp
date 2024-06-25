//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Ilias Khairullin <ilias@nil.foundation>
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

#ifndef CRYPTO3_ALGEBRA_FIELDS_VESTA_SCALAR_FIELD_HPP
#define CRYPTO3_ALGEBRA_FIELDS_VESTA_SCALAR_FIELD_HPP

#ifndef __ZKLLVM__
#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#endif

#include <nil/crypto3/algebra/fields/params.hpp>
#include <nil/crypto3/algebra/fields/field.hpp>
#include <nil/crypto3/algebra/fields/pallas/base_field.hpp>



namespace nil {
    namespace crypto3 {
        namespace algebra {
            namespace fields {
                /**
                 * @brief A struct representing a vesta curve.
                 */
#ifdef __ZKLLVM__
                    class vesta_scalar_field {
                    public:
                        typedef __zkllvm_field_vesta_scalar value_type;
                    };
#else
                using vesta_scalar_field = pallas_base_field;

                using vesta_fr = vesta_scalar_field;
#endif
            }    // namespace fields
        }        // namespace algebra
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ALGEBRA_FIELDS_VESTA_SCALAR_FIELD_HPP
