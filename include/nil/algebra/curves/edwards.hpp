//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_CURVES_EDWARDS_HPP
#define ALGEBRA_CURVES_EDWARDS_HPP

#include <nil/algebra/curves/detail/edwards/g1.hpp>
#include <nil/algebra/curves/detail/edwards/g2.hpp>
#include <nil/algebra/curves/detail/edwards/basic_policy.hpp>

#include <nil/algebra/fields/edwards/fq.hpp>
#include <nil/algebra/fields/edwards/fr.hpp>
#include <nil/algebra/fields/detail/params/edwards/fq.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace curves {

            using namespace algebra;

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            struct edwards { };

            template<>
            struct edwards<183, CHAR_BIT> : public edwards_basic_policy<183, CHAR_BIT> {

                using policy_type = edwards_basic_policy<183>;

                typedef typename policy_type::base_field_type base_field_type;
                typedef typename policy_type::scalar_field_type scalar_field_type;
                typedef typename policy_type::modulus_type number_type;

                typedef typename detail::edwards_g1<183> g1_type;
                typedef typename detail::edwards_g2<183> g2_type;
                typedef typename nil::algebra::fields::detail::element_fp6_2over3<
                    nil::algebra::fields::detail::arithmetic_params<edwards<183, CHAR_BIT>>>
                    gt_type;

                typedef std::vector<typename g1_type> g1_vector;
                typedef std::vector<typename g2_type> g2_vector;
            };

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            using edwards_g1 = typename edwards<ModulusBits, GeneratorBits>::g1_type;

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            using edwards_g2 = typename edwards<ModulusBits, GeneratorBits>::g2_type;

            template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
            using edwards_gt = typename edwards<ModulusBits, GeneratorBits>::gt_type;

        }    // namespace curves
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_CURVES_EDWARDS_HPP
