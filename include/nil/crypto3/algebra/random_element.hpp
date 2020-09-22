//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP
#define CRYPTO3_ALGEBRA_RANDOM_ELEMENT_HPP

namespace nil {
    namespace crypto3 {
        namespace algebra {

            template<typename CurveGType>    // use curve croup element type_trait
            CurveGType curve_random_element() {
                return CurveGType::one();
            };

            template<typename FieldType>    // use field element type_trait
            typename FieldType::value_type field_random_element() {
                return FieldType::value_type::one();
            };

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_RANDOM_ELEMENT_HPP
