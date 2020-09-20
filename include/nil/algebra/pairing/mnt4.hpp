//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_MNT4_POLICY_HPP
#define ALGEBRA_PAIRING_MNT4_POLICY_HPP

#include <nil/algebra/pairing/detail/mnt4/functions.hpp>
#include <nil/algebra/pairing/policy.hpp>

#include <nil/algebra/curves/mnt4.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            struct pairing_policy<mnt4<ModulusBits, GeneratorBits>> {

                using other_curve = curves::mnt6<ModulusBits, GeneratorBits>;

                typedef typename mnt4_basic_policy::scalar_field_type FieldType;
                typedef algebra::Fqe<algebra::curves::mnt6> fqe_type;
                typedef algebra::Fqk<algebra::curves::mnt6> fqk_type;

                using g1_precomp = detail::g1_precomp<ModulusBits, GeneratorBits>;
                using g2_precomp = detail::g2_precomp<ModulusBits, GeneratorBits>;

                using precompute_g1 = detail::precompute_g1<ModulusBits, GeneratorBits>;
                using precompute_g2 = detail::precompute_g2<ModulusBits, GeneratorBits>;

                using reduced_pairing = detail::reduced_pairing<ModulusBits, GeneratorBits>;
                using pairing = detail::pairing<ModulusBits, GeneratorBits>;

                using miller_loop = detail::miller_loop<ModulusBits, GeneratorBits>;
                using double_miller_loop = detail::double_miller_loop<ModulusBits, GeneratorBits>;
                using final_exponentiation = detail::final_exponentiation<ModulusBits, GeneratorBits>;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT4_POLICY_HPP