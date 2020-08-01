//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef ALGEBRA_PAIRING_BN128_HPP
#define ALGEBRA_PAIRING_BN128_HPP

#include <nil/crypto3/algebra/curves/curve_jacobian.hpp>

namespace nil {
    namespace algebra {

        BOOST_MP_DEFINE_SIZED_CPP_INT_LITERAL(256)
        /*
			y^2 = x^3 + b
			u^2 = -1
			xi = xi_a + xi_b u
			v^3 = xi
			w^2 = v
		*/
        struct bn128_snark1 : public curve_jacobian_policy<256> {
	        typedef typename ec_group_info<256>::number_type number_type;

	        constexpr static const number_type p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
	        constexpr static const number_type a =
	            ?;
	        constexpr static const number_type b = 0x03;
	        constexpr static const number_type x = 0x09;
	        constexpr static const number_type y = 0x01;
	        constexpr static const number_type order =
	        	?;
    	};

    	// b/xi = 82 / (9 + u) = 9 - u
        struct bn128_snark2 : public curve_jacobian_policy<256> {
	        typedef typename ec_group_info<256>::number_type number_type;

	        constexpr static const number_type p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
	        constexpr static const number_type a =
	            ?;
	        constexpr static const number_type b = 82;
	        constexpr static const number_type x = 0x09;
	        constexpr static const number_type y = 0x01;
	        constexpr static const number_type order =
	        	?;
    	};

    	// herumi curve
        struct bn128_Fp254BNb : public curve_jacobian_policy<256> {
	        typedef typename ec_group_info<256>::number_type number_type;

	        constexpr static const number_type p = 16798108731015832284940804142231733909889187121439069848933715426072753864723;
	        constexpr static const number_type a =
	            ?;
	        constexpr static const number_type b = 0x2;
	        constexpr static const number_type x = 0x01;
	        constexpr static const number_type y = 0x01;
	        constexpr static const number_type order =
	        	?;
    	};

    }    // namespace algebra
}    // namespace nil

#endif    // ALGEBRA_PAIRING_BN128_HPP
