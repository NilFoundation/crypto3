//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_FFDHE_IETF_PARAMS_HPP
#define ALGEBRA_FIELDS_FFDHE_IETF_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>

#include <nil/algebra/detail/mp_def.hpp>

namespace nil {
    namespace algebra {
        namespace fields {

            template<std::size_t ModulusBits, std::size_t GeneratorBits>
            struct ffdhe_ietf;

            namespace detail {
            	
                template<std::size_t ModulusBits, std::size_t GeneratorBits = CHAR_BIT>
                struct arithmetic_params<ffdhe_ietf<ModulusBits, GeneratorBits>> : public params<modp_srp<ModulusBits, GeneratorBits>> {
                private:
                    typedef params<modp_srp<ModulusBits, GeneratorBits>> policy_type;
                    typedef arithmetic_params<modp_srp<ModulusBits, GeneratorBits>> element_policy_type;
                public:
                    typedef typename policy_type::number_type number_type;

                    constexpr static const modulus_type q = 0;
                };
            
            }    // namespace detail
        }    // namespace fields
    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_FFDHE_IETF_PARAMS_HPP
