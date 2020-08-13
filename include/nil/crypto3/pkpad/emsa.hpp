//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_PUBKEY_EMSA_HPP
#define CRYPTO3_PUBKEY_EMSA_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

namespace nil {
    namespace crypto3 {

        class private_key_policy;

        class random_number_generator;

        /*!
         * @brief  EMSA, from IEEE 1363s Encoding Method for Signatures, Appendix
         *
         * @tparam Scheme
         * @tparam Hash
         */
        template<typename Scheme, typename Hash>
        struct emsa {
            typedef Hash hash_type;
            typedef Scheme scheme_type;
        };
    }    // namespace crypto3
}    // namespace nil

#endif
