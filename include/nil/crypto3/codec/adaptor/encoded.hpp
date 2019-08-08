//---------------------------------------------------------------------------//
// Copyright (c) 2018-2019 Nil Foundation AG
// Copyright (c) 2018-2019 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ENCODED_HPP
#define CRYPTO3_ENCODED_HPP

#include <boost/range/adaptor/argument_fwd.hpp>
#include <boost/range/detail/default_constructible_unary_fn.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/range/concepts.hpp>

#include <boost/iterator/transform_iterator.hpp>

#include <boost/variant/variant.hpp>

#include <boost/utility/result_of.hpp>

#include <nil/crypto3/codec/codec_value.hpp>

namespace nil {
    namespace crypto3 {
        namespace codec {
            namespace adaptors {
                template<typename Encoder, typename StreamCodec>
                struct encoded {
                public:
                    encoded(const StreamCodec &ise = StreamCodec()) : val(ise) {
                    }

                    StreamCodec val;
                };

                template<typename Encoder,
                         typename SinglePassRange,
                         typename StreamCodec = typename detail::
                             range_codec_state_traits<typename Encoder::stream_encoder_type, SinglePassRange>::type>
                inline detail::range_codec_impl<detail::ref_codec_impl<StreamCodec>>
                    operator|(SinglePassRange &r, const encoded<Encoder, StreamCodec> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    return detail::range_codec_impl<detail::ref_codec_impl<StreamCodec>>(r, f.val);
                }

                template<typename Encoder,
                         typename SinglePassRange,
                         typename StreamCodec = typename detail::
                             range_codec_state_traits<typename Encoder::stream_encoder_type, SinglePassRange>::type>
                inline detail::range_codec_impl<detail::ref_codec_impl<StreamCodec>>
                    operator|(const SinglePassRange &r, const encoded<Encoder, StreamCodec> &f) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<const SinglePassRange>));

                    return detail::range_codec_impl<detail::ref_codec_impl<StreamCodec>>(r, f.val);
                }
            };    // namespace adaptors
        }         // namespace codec
    }             // namespace crypto3
}    // namespace nil
#endif    // CRYPTO3_ENCODED_HPP
