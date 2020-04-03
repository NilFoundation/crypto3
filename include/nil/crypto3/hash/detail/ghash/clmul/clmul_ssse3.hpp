//---------------------------------------------------------------------------//
// Copyright (c) 2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_GCM_CLMUL_SSSE3_HPP
#define CRYPTO3_GCM_CLMUL_SSSE3_HPP

#include <nil/crypto3/utilities/types.hpp>

namespace nil {
    namespace crypto3 {
        void gcm_multiply_ssse3(uint8_t x[16], const uint64_t HM[256], const uint8_t input[], size_t blocks);
    }
}
#endif
