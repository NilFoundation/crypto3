//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation
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

                template<typename EncoderMode,
                         typename SinglePassRange> using range_codec_state_traits = typename EncoderMode::encoder_type::template stream_processor<
                        EncoderMode, std::numeric_limits<
                                typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits +
                                     std::numeric_limits<typename std::iterator_traits<
                                             typename SinglePassRange::iterator>::value_type>::is_signed>;

                template<typename EncoderMode,
                         typename InputIterator> using itr_codec_state_traits = typename EncoderMode::encoder_type::template stream_processor<
                        EncoderMode, std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits +
                                     std::numeric_limits<
                                             typename std::iterator_traits<InputIterator>::value_type>::is_signed>;
            }
        }
    }
}

#endif //CRYPTO3_CODEC_TYPE_TRAITS_HPP
