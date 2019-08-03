//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_ACCUMULATORS_PARAMETERS_SALT_HPP
#define CRYPTO3_HASH_ACCUMULATORS_PARAMETERS_SALT_HPP

#include <boost/parameter/keyword.hpp>

#include <boost/accumulators/accumulators_fwd.hpp>

namespace nil {
    namespace crypto3 {
        namespace accumulators {
            BOOST_PARAMETER_KEYWORD(tag, salt)
            BOOST_ACCUMULATORS_IGNORE_GLOBAL(salt)
        }    // namespace accumulators
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PARAMETERS_HPP
