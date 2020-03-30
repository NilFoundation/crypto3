//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_OCTET_HPP
#define CRYPTO3_OCTET_HPP

#include <boost/integer.hpp>

namespace nil {
    namespace crypto3 {
        constexpr static const std::size_t octet_bits = CHAR_BIT;
        typedef boost::uint_t<octet_bits>::least octet_type;
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_OCTET_HPP
