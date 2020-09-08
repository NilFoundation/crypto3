//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MNT6_FR_PARAMS_HPP
#define ALGEBRA_FIELDS_MNT6_FR_PARAMS_HPP

#include <nil/algebra/fields/detail/element/fp.hpp>
#include <nil/algebra/fields/detail/element/fp2.hpp>
#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/fields/mnt6/fr.hpp>

#include <nil/algebra/detail/literals.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

                template<std::size_t ModulusBits, std::size_t GeneratorBits>
                struct extension_params<mnt6_fr<ModulusBits, GeneratorBits>>
                    : public params<mnt6_fr<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<mnt6_fr<ModulusBits, GeneratorBits>> policy_type;
                    typedef extension_params<mnt6_fr<ModulusBits, GeneratorBits>> element_policy_type;

                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const number_type q =
                        0x1DE7BDE6A39D133124ED3D82A47657764B1AE89987520D4F1AF2890070964866B2D38B30000_cppui297;
                };

            }    // namespace detail
        }        // namespace fields
    }            // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MNT6_FR_PARAMS_HPP
