//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_HASHED_HPP
#define CRYPTO3_HASHED_HPP

#include <boost/range/concepts.hpp>
#include <boost/range/adaptor/argument_fwd.hpp>

#include <nil/crypto3/hash/hash_value.hpp>
#include <nil/crypto3/hash/hash_state.hpp>

namespace nil {
    namespace crypto3 {
        namespace hashes {
            namespace detail {
                template<typename HashAccumulator, typename SinglePassRange>
                inline detail::range_hash_impl<detail::value_hash_impl<HashAccumulator>>
                    operator|(SinglePassRange &r, const detail::value_hash_impl<HashAccumulator> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                    typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                    return HashImpl(r, HashAccumulator());
                }

                template<typename HashAccumulator, typename SinglePassRange>
                inline detail::range_hash_impl<detail::value_hash_impl<HashAccumulator>>
                    operator|(const SinglePassRange &r, const detail::value_hash_impl<HashAccumulator> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    typedef detail::value_hash_impl<HashAccumulator> StreamHashImpl;
                    typedef detail::range_hash_impl<StreamHashImpl> HashImpl;

                    return HashImpl(r, HashAccumulator());
                }
            }    // namespace detail
        }        // namespace hashes

        namespace adaptors {
            namespace {
                template<typename Hash, typename HashAccumulator = accumulator_set<Hash>>
                const hashes::detail::value_hash_impl<HashAccumulator>
                    hashed = hashes::detail::value_hash_impl<HashAccumulator>(HashAccumulator());
            }
        }    // namespace adaptors
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_HASHED_HPP
