//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_MNT4_HPP
#define ALGEBRA_CURVES_MNT4_HPP

#include <nil/algebra/curves/detail/mnt4/basic_policy.hpp>
#include <nil/algebra/curves/detail/mnt4/g1.hpp>
#include <nil/algebra/curves/detail/mnt4/g2.hpp>

#include <nil/algebra/pairing/mnt4.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            using namespace nil::algebra;

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            struct mnt4 {

                using policy_type = detail::mnt4_basic_policy<ModulusBits, GeneratorBits>;

                typedef typename policy_type::base_field_type base_field_type;
                typedef typename policy_type::scalar_field_type scalar_field_type;
                typedef typename policy_type::number_type number_type;
                typedef typename policy_type::extended_number_type extended_number_type;

                constexpr static const std::size_t base_field_bits = policy_type::base_field_bits;
                constexpr static const number_type p = policy_type::p;

                constexpr static const std::size_t scalar_field_bits = policy_type::scalar_field_bits;
                constexpr static const number_type q = policy_type::q;

                typedef typename detail::mnt4_g1<base_field_bits, CHAR_BIT> g1_type;
                typedef typename detail::mnt4_g2<base_field_bits, CHAR_BIT> g2_type;

                typedef typename pairing::pairing_policy<mnt4<ModulusBits, GeneratorBits>> pairing_policy;

                typedef typename policy_type::gt_type gt_type;

                typedef std::vector<g1_type> g1_vector;
                typedef std::vector<g2_type> g2_vector;
            };

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_g1 = typename mnt4<ModulusBits, GeneratorBits>::g1_type;

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_g2 = typename mnt4<ModulusBits, GeneratorBits>::g2_type;

            template<std::size_t ModulusBits = 298, std::size_t GeneratorBits = CHAR_BIT>
            using mnt4_gt = typename mnt4<ModulusBits, GeneratorBits>::gt_type;

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_MNT4_HPP
