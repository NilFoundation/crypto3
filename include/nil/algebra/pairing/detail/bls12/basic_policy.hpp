//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP
#define ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP

#include <nil/algebra/curves/bls12.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                template<std::size_t ModulusBits = 381, std::size_t GeneratorBits = CHAR_BIT>
                struct basic_policy<bls12<ModulusBits, GeneratorBits>> {

                    using number_type = bls12<ModulusBits, GeneratorBits>::number_type;

                    loop_count
                };

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_PAIRING_BLS128_BASIC_POLICY_HPP
