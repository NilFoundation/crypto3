//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_FIELDS_DSA_JCE_PARAMS_HPP
#define ALGEBRA_FIELDS_DSA_JCE_PARAMS_HPP

#include <nil/algebra/fields/detail/params/params.hpp>
#include <nil/algebra/fields/dsa_jse.hpp>

namespace nil {
    namespace algebra {
    	namespace fields {
	        namespace detail {

	        	BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
	        	
	            struct arithmetic_params<dsa_jse<1024>> : public params<dsa_jce<1024>> {
	                constexpr static const number_type q = 0x9760508F15230BCCB292B982A2EB840BF0581CF5_cppui160;
	            };

	        }    // namespace detail
        }    // namespace fields
    }        // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_FIELDS_DSA_JCE_PARAMS_HPP
