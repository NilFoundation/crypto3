//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_MNT6_POLICY_HPP
#define ALGEBRA_PAIRING_MNT6_POLICY_HPP

#include <sstream>

#include <nil/algebra/pairing/ate.hpp>
#include <nil/algebra/pairing/detail/mnt6/functions.hpp>

#include <nil/algebra/curves/mnt6.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            struct pairing_policy<mnt6<ModulusBits, GeneratorBits>> {

                using other_curve = curves::mnt4<ModulusBits, GeneratorBits>;

                typedef typename curves::mnt6::scalar_field_type FieldType;
                typedef algebra::Fqe<algebra::curves::mnt6> fqe_type;
                typedef algebra::Fqk<algebra::curves::mnt6> fqk_type;

                using g1_precomp = detail::mnt6_g1_precomp<ModulusBits, GeneratorBits>;
                using g2_precomp = detail::mnt6_g2_precomp<ModulusBits, GeneratorBits>;

                using precompute_g1 = detail::mnt6_precompute_g1<ModulusBits, GeneratorBits>;
                using precompute_g2 = detail::mnt6_precompute_g2<ModulusBits, GeneratorBits>;

                using reduced_pairing = detail::reduced_pairing<ModulusBits, GeneratorBits>;
                using pairing = detail::pairing<ModulusBits, GeneratorBits>;

                using miller_loop = detail::mnt6_miller_loop<ModulusBits, GeneratorBits>;
                using double_miller_loop = detail::mnt6_double_miller_loop<ModulusBits, GeneratorBits>;
                using final_exponentiation = detail::mnt6_final_exponentiation<ModulusBits, GeneratorBits>;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT6_POLICY_HPP