//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_DSA_BOTAN_PARAMS_HPP
#define ALGEBRA_FIELDS_DSA_BOTAN_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/dsa_botan.hpp>


namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {
                BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)

                template <>
                struct arithmetic_params<dsa_botan<2048, 2048>> : public params<dsa_botan<2048, 2048>> {
                private:
                    typedef params<dsa_botan<2048, 2048>> policy_type;
                    typedef arithmetic_params<dsa_botan<2048, 2048>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const number_type q =
                        0x8CD7D450F86F0AD94EEE4CE469A8756D1EBD1058241943EAFFB0B354585E924D_cppui256;
                };

                template <>
                struct arithmetic_params<dsa_botan<3072, 3072>> : public params<dsa_botan<3072, 3072>> {
                private:
                    typedef params<dsa_botan<3072, 3072>> policy_type;
                    typedef arithmetic_params<dsa_botan<3072, 3072>> element_policy_type;
                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const number_type q =
                        0xB3EBD364EC69EF8CF3BAF643B75734B16339B2E49E5CDE1B59C1E9FB40EE0C5B_cppui256;
                };
            }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_BOTAN_PARAMS_HPP
