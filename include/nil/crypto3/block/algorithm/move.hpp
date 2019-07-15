//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLOCK_MOVE_HPP
#define CRYPTO3_BLOCK_MOVE_HPP

#include <algorithm>

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

namespace nil {
    namespace crypto3 {
        namespace block {
            template<typename SinglePassRange, typename OutputIterator>
            inline OutputIterator move(const SinglePassRange &rng, OutputIterator result) {
                return std::move(boost::begin(rng), boost::end(rng), result);
            }
        }    // namespace block
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_BLOCK_MOVE_HPP
