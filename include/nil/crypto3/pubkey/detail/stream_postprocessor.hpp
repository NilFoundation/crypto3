#ifndef CRYPTO3_PUBKEY_STREAM_POSTPROCESSOR_HPP
#define CRYPTO3_PUBKEY_STREAM_POSTPROCESSOR_HPP

#include <boost/assert.hpp>
#include <boost/concept_check.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range/concepts.hpp>

#include <nil/crypto3/pubkey/detail/digest.hpp>
#include <nil/crypto3/pubkey/detail/static_digest.hpp>

#include <nil/crypto3/utilities/type_traits/is_iterator.hpp>

namespace nil {
    namespace crypto3 {
        namespace detail {
            template<typename Encrypter, typename SinglePassRange>
            using range_stream_encrypt_traits = typename Encrypter::template stream_encrypt<
                std::numeric_limits<
                    typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::digits
                + std::numeric_limits<
                    typename std::iterator_traits<typename SinglePassRange::iterator>::value_type>::is_encrypted>;

            template<typename Encrypter, typename InputIterator>
            using itr_stream_encrypt_traits = typename Encrypter::template stream_encrypt<
                std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::digits
                + std::numeric_limits<typename std::iterator_traits<InputIterator>::value_type>::is_encrypted>;

            template<typename StreamHash>
            struct ref_encrypt_impl {
                typedef StreamHash stream_encrypt_type;

                ref_encrypt_impl(const StreamHash &stream_encrypt) : sh(std::move(stream_encrypt)) {
                }

                template<typename Result>
                Result result() const {
                    return sh.digest();
                }

                StreamHash &sh;
            };

            template<typename StreamHash>
            struct value_encrypt_impl {
                typedef StreamHash stream_encrypt_type;

                value_encrypt_impl(const StreamHash &stream_encrypt) : sh(stream_encrypt) {
                }

                template<typename Result>
                Result result() const {
                    return sh.end_message();
                }

                mutable StreamHash sh;
            };

            template<typename Encrypter, typename StreamEncrypterImpl>
            struct range_encrypt_impl : public StreamEncrypterImpl {
            public:
                template<typename SinglePassRange>
                range_encrypt_impl(const SinglePassRange &range,
                                   const typename StreamEncrypterImpl::stream_encrypt_type &ish) :
                    StreamEncrypterImpl(ish) {
                    BOOST_RANGE_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(boost::begin(range), boost::end(range));
                }

                template<typename InputIterator>
                range_encrypt_impl(InputIterator first, InputIterator last,
                                   const typename StreamEncrypterImpl::stream_encrypt_type &ish) :
                    StreamEncrypterImpl(ish) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(first, last);
                }

                template<typename OutputRange>
                operator OutputRange() const {
                    const auto &range = this->template result<typename Encrypter::digest_type>();

                    return OutputRange(range.begin(), range.end());
                }

                operator typename Encrypter::digest_type() const {
                    return this->template result<typename Encrypter::digest_type>();
                }

#ifndef CRYPTO3_RAW_HASH_STRING_OUTPUT

                template<typename Char, typename CharTraits, typename Alloc>
                operator std::basic_string<Char, CharTraits, Alloc>() const {
                    return std::to_string(this->template result<typename Encrypter::digest_type>());
                }

#endif
            };

            template<typename Encrypter, typename StreamEncrypterImpl, typename OutputIterator>
            struct itr_encrypt_impl : public StreamEncrypterImpl {
            private:
                mutable OutputIterator out;

            public:
                template<typename SinglePassRange>
                itr_encrypt_impl(const SinglePassRange &range, OutputIterator out,
                                 const typename StreamEncrypterImpl::stream_encrypt_type &ish) :
                    StreamEncrypterImpl(ish),
                    out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::SinglePassRangeConcept<SinglePassRange>));

                    typedef typename std::iterator_traits<typename SinglePassRange::iterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(boost::begin(range), boost::end(range));
                }

                template<typename InputIterator>
                itr_encrypt_impl(InputIterator first, InputIterator last, OutputIterator out,
                                 const typename StreamEncrypterImpl::stream_encrypt_type &ish) :
                    StreamEncrypterImpl(ish),
                    out(std::move(out)) {
                    BOOST_CONCEPT_ASSERT((boost::InputIteratorConcept<InputIterator>));

                    typedef typename std::iterator_traits<InputIterator>::value_type value_type;

                    BOOST_STATIC_ASSERT(std::numeric_limits<value_type>::is_specialized);

                    this->sh.update(first, last);
                }

                operator OutputIterator() const {
                    const auto &result = this->template result<typename Encrypter::digest_type>();

                    return std::move(result.begin(), result.end(), out);
                }
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_STREAM_POSTPROCESSOR_HPP
