//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP
#define ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP

#include <nil/algebra/curves/detail/edwards/basic_policy.hpp>

namespace nil {
    namespace algebra {
        namespace pairing {
            namespace detail {

                using namespace nil::algebra;

                template<std::size_t ModulusBits = 183, std::size_t GeneratorBits = CHAR_BIT>
                struct edwards_basic_policy;

                template<>
                struct edwards_basic_policy<183, CHAR_BIT> {

                    using number_type = curves::detail::edwards_basic_policy<183, CHAR_BIT>::number_type;
                    using extended_number_type = curves::detail::edwards_basic_policy<183, CHAR_BIT>::extended_number_type;

                    constexpr static const number_type final_exponent_last_chunk_abs_of_w0 =
                        number_type(0x3A1077BB02A78E4A00000003_cppui94);
                    constexpr static const bool final_exponent_last_chunk_is_w0_neg = true;

                    constexpr static const number_type final_exponent_last_chunk_w1 = number_type(0x4);

                    constexpr static const extended_number_type final_exponent = extended_number_type(
                        0x11128FF78CE1BA3ED7BDC08DC0E8027077FC9348F971A3EF1053C9D33B1AA7CEBA86030D02292F9F5E784FDE9EE9D0176DBE7DA7ECBBCB64CDC0ACD4E64D7156C2F84EE1AAFA1098707148DB1E4797E330E5D507E78D8246A4843B4A174E7CD7CA937BDC5D67A6176F9A48984764500000000_cppui913);
                };

            }    // namespace detail
        }        // namespace pairing
    }            // namespace algebra
}    // namespace nil
#endif    // ALGEBRA_PAIRING_EDWARDS_BASIC_POLICY_HPP