//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_ELEMENT_BN128_FR_HPP
#define ALGEBRA_FIELDS_ELEMENT_BN128_FR_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/bn128/fr.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct element_bn128_fr : public element_fp<ModulusBits, GeneratorBits> {
                };
                
            }   // namespace detail
        }   // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_ELEMENT_BN128_FR_HPP
