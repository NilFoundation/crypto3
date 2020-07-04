//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASH_STATE_HPP
#define CRYPTO3_HASH_STATE_HPP

#include <boost/accumulators/framework/accumulator_set.hpp>
#include <boost/accumulators/framework/features.hpp>

#include <nil/crypto3/detail/type_traits.hpp>

#include <nil/crypto3/hash/accumulators/hash.hpp>

namespace nil {
    namespace crypto3 {
        template<typename Hash, typename = typename std::enable_if<detail::is_hash<Hash>::value>::type>
        using accumulator_set =
            boost::accumulators::accumulator_set<static_digest<Hash::digest_bits>,
                                                 boost::accumulators::features<accumulators::tag::hash<Hash>>,
                                                 std::size_t>;
    }    // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_STREAM_PREPROCESSOR_HPP