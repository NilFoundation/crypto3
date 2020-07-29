//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_HPP
#define ALGEBRA_FIELDS_ELEMENT_HPP

#include <array>
#include <nil/algebra/fields/detail/params/params.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            template<typename Field, typename NumberType>
            struct element {
            	using type = std::array<NumberType, basic_params<Field>::arity>;
            }

            template<typename NumberType>
            struct element<fp4> {
            	using type = std::array<element<fp2, NumberType>, 2>;
            }
            
            template<typename NumberType>
            struct element<fp6_3over2> {
            	using type = std::array<element<fp2, NumberType>, 3>;
            }

            template<typename NumberType>
            struct element<fp6_2over3> {
            	using type = std::array<element<fp3, NumberType>, 2>;
            }

            template<typename NumberType>
            struct element<fp12_2over3over2> {
            	using type = std::array<element<fp6_3over2, NumberType>, 2>;
            }
        }
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_HPP
