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
        namespace curves {
            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct mnt4;
        }    // namespace curves
        namespace pairing {

            using namespace nil::algebra;
            
            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            class pairing_policy<curves::mnt4<ModulusBits, GeneratorBits>> {
                using policy_type = detail::mnt4_pairing_functions<ModulusBits, GeneratorBits>;
            public:

                using other_curve = curves::mnt6<ModulusBits, GeneratorBits>;

                typedef typename policy_type::scalar_field_type FieldType;
                typedef algebra::Fqe<algebra::curves::mnt6> fqe_type;
                typedef algebra::Fqk<algebra::curves::mnt6> fqk_type;

                using g1_precomp = policy_type::g1_precomp;
                using g2_precomp = policy_type::g2_precomp;

                using precompute_g1 = policy_type::precompute_g1;
                using precompute_g2 = policy_type::precompute_g2;

                using reduced_pairing = policy_type::reduced_pairing;
                using pairing = policy_type::pairing;

                using miller_loop = policy_type::miller_loop;
                using double_miller_loop = policy_type::double_miller_loop;
                using final_exponentiation = policy_type::final_exponentiation;
            };
        }    // namespace pairing
    }        // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_MNT4_POLICY_HPP