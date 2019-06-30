//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nilfoundation.org>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_CODEC_TYPE_TRAITS_HPP
#define CRYPTO3_CODEC_TYPE_TRAITS_HPP

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace detail {
                template<typename CodecState>
                struct is_codec_state {
                    struct two {
                        char _[2];
                    };

                    template<typename X>
                    constexpr static char test(int, typename X::mode_type *);

                    template<typename X>
                    constexpr static two test(int, ...);

                    constexpr static const bool value = (1 == sizeof(test<CodecState>(0, 0)));
                };
            }
        }
    }
}

#endif //CRYPTO3_CODEC_TYPE_TRAITS_HPP
