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

            template<typename Type1, typename Type2>
            Type2 random_element();

            template<typename CurveGType>    // use curve croup element type_trait
            CurveGType random_element<CurveGType, CurveGType>() {
                return CurveGType::one();
            };

            template<typename FieldType>    // use field element type_trait
            typename FieldType::value_type random_element<FieldType, FieldType::value_type>() {
                return FieldType::value_type::one();
            };

        }    // namespace algebra
    }        // namespace crypto3
}    // namespace nil
#endif    // ALGEBRA_RANDOM_ELEMENT_HPP
