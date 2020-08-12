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

namespace nil {
    namespace algebra {
        template<typename Field>
        struct element {
        	typedef arithmetic_params<Field> params_type;
        };

        struct element_fp : public element<element_fp> {

        };
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_HPP
