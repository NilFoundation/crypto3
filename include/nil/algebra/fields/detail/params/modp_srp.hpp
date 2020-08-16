//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_MODP_SRP_PARAMS_HPP
#define ALGEBRA_FIELDS_MODP_SRP_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>
#include <nil/algebra/fields/modp_srp.hpp>

namespace nil {
    namespace algebra {
        namespace fields {
            namespace detail {

            	BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
            	
                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct arithmetic_params<modp_srp<ModulusBits, GeneratorBits>> : public params<modp_srp<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<modp_srp<ModulusBits, GeneratorBits>> policy_type;
                    typedef arithmetic_params<modp_srp<ModulusBits, GeneratorBits>> element_policy_type;
                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const number_type q = 0;
                };
            
            }    // namespace detail
        }    // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_MODP_SRP_PARAMS_HPP
