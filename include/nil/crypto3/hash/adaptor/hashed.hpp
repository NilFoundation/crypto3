//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
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
