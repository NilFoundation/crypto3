#ifndef CRYPTO3_PUBKEY_STREAM_PREPROCESSOR_HPP
#define CRYPTO3_PUBKEY_STREAM_PREPROCESSOR_HPP

#include <array>
#include <iterator>

#include <nil/crypto3/pubkey/pack.hpp>
#include <nil/crypto3/pubkey/algorithm/move.hpp>
#include <nil/crypto3/pubkey/digest.hpp>

#include <nil/crypto3/utilities/secmem.hpp>

#include <boost/integer.hpp>
#include <boost/static_assert.hpp>
#include <boost/utility/enable_if.hpp>

#include <boost/container/small_vector.hpp>

#include <boost/range/algorithm/copy.hpp>

namespace nil {
    namespace crypto3 {
        namespace pubkey {
            template<typename Cipher, typename Padding>
            struct nop_cipher_mode {
                typedef typename Cipher::pubkey_type pubkey_type;

                pubkey_type begin_message(const pubkey_type &plaintext) {
                }

                pubkey_type process_pubkey(const pubkey_type &plaintext) {
                }

                pubkey_type end_message(const pubkey_type &plaintext) {
                }
            };

            struct nop_finalizer {
                template<typename T>
                void operator()(T &) {
                }
            };

            template<typename Mode,
                     typename Endian,
                     std::size_t ValueBits,
                     std::size_t LengthBits,
                     template<typename> class StateAppendFunctor = std::back_insert_iterator,
                     typename FinalizerFunctor = nop_finalizer>
            class stream_preprocessor {
            public:
                typedef Mode cipher_mode_type;
                typedef typename cipher_mode_type::cipher_type cipher_type;
                typedef typename cipher_mode_type::padding_type cipher_padding_type;

                template<typename T>
                using state_append_functor = StateAppendFunctor<T>;

                typedef FinalizerFunctor finalizer_functor;

                typedef digest<LengthBits> digest_type;

                constexpr static const std::size_t word_bits = cipher_type::word_bits;
                typedef typename cipher_type::word_type word_type;

                constexpr static const std::size_t pubkey_bits = cipher_type::pubkey_bits;
                constexpr static const std::size_t pubkey_words = cipher_type::pubkey_words;
                typedef typename cipher_type::pubkey_type pubkey_type;

                constexpr static const std::size_t value_bits = ValueBits;
                typedef typename boost::uint_t<value_bits>::least value_type;
                BOOST_STATIC_ASSERT(word_bits % value_bits == 0);
                constexpr static const std::size_t pubkey_values = pubkey_bits / value_bits;
                typedef std::array<value_type, pubkey_values> value_array_type;

            private:
                constexpr static const std::size_t length_bits = LengthBits;
                // FIXME: do something more intelligent than capping at 64
                constexpr static const std::size_t length_type_bits =
                    length_bits < word_bits ? word_bits : length_bits > 64 ? 64 : length_bits;
                typedef typename boost::uint_t<length_type_bits>::least length_type;
                constexpr static const std::size_t length_words = length_bits / word_bits;
                BOOST_STATIC_ASSERT(!length_bits || length_bits % word_bits == 0);
                BOOST_STATIC_ASSERT(pubkey_bits % value_bits == 0);

                BOOST_STATIC_ASSERT(!length_bits || value_bits <= length_bits);

            private:
                void process_pubkey() {
                    // Convert the input into words
                    pubkey_type pubkey;
                    pack<Endian, value_bits, word_bits>(value_array, pubkey);

                    // Process the pubkey
                    move(c.encrypt(pubkey), state_append_functor<digest_type>(result));

                    // Reset seen if we don't need to track the length
                    if (!length_bits) {
                        seen = 0;
                    }
                }

            public:
                stream_preprocessor &update_one(value_type value) {
                    unsigned i = seen % pubkey_bits;
                    unsigned j = i / value_bits;
                    value_array[j] = value;
                    seen += value_bits;
                    if (i == pubkey_bits - value_bits) {
                        // Process the completed pubkey
                        process_pubkey();
                    }
                    return *this;
                }

                template<typename InputIterator>
                stream_preprocessor &update_n(InputIterator p, size_t n) {
#ifndef CRYPTO3_PUBKEY_NO_OPTIMIZATION
                    for (; n && (seen % pubkey_bits); --n, ++p) {
                        update_one(*p);
                    }
                    for (; n >= pubkey_values; n -= pubkey_values, p += pubkey_values) {
                        // Convert the input into words
                        pubkey_type pubkey;
                        pack_n<Endian, value_bits, word_bits>(p, pubkey_values, &pubkey[0], pubkey_words);

                        // Process the pubkey
                        move(c.encrypt(pubkey), state_append_functor<digest_type>(result));
                        seen += pubkey_bits;

                        // Reset seen if we don't need to track the length
                        if (!length_bits) {
                            seen = 0;
                        }
                    }
#endif
                    for (; n; --n, ++p) {
                        update_one(*p);
                    }
                    return *this;
                }

                template<typename InputIterator>
                stream_preprocessor &update(InputIterator b, InputIterator e, std::random_access_iterator_tag) {
                    return update_n(b, e - b);
                }

                template<typename InputIterator, typename Category>
                stream_preprocessor &update(InputIterator first, InputIterator last, Category) {
                    while (first != last) {
                        update_one(*first++);
                    }
                    return *this;
                }

                template<typename InputIterator>
                stream_preprocessor &update(InputIterator b, InputIterator e) {
                    typedef typename std::iterator_traits<InputIterator>::iterator_category cat;
                    return update(b, e, cat());
                }

                template<typename ContainerT>
                stream_preprocessor &update(const ContainerT &c) {
                    return update_n(c.data(), c.size());
                }

                digest_type end_message() {
                    length_type length = seen;

                    // Add a 1 bit
#ifdef CRYPTO3_PUBKEY_NO_OPTIMIZATION
                    std::array<bool, ValueBits> padding_bits = {{1}};
                    std::array<value_type, 1> padding_values;
                    pack<Endian, 1, ValueBits>(padding_bits, padding_values);
                    update_one(padding_values[0]);
#else
                    value_type pad = 0;
                    detail::imploder_step<Endian, 1, value_bits, 0>::step(1, pad);
                    update_one(pad);
#endif

                    // Pad with 0 bits
                    while ((seen + length_bits) % pubkey_bits != 0) {
                        update_one(value_type());
                    }

                    // Reset for next message
                    seen = 0;

                    // Calculate static_digest and reset c
                    finalizer_functor finalizer;
                    finalizer(result);

                    digest_type d;
                    pack_n<Endian, word_bits, octet_bits>(result.data(), word_bits, d.data(), octet_bits);
                    reset();

                    return d;
                }

                digest_type digest() const {
                    return boost::range::copy(end_message(), state_append_functor<digest_type>(result));
                }

            public:
                stream_preprocessor(const cipher_type &cipher = cipher_type()) :
                    result(), value_array(), c(cipher, cipher_padding_type()), seen() {
                }

                stream_preprocessor(const cipher_mode_type &mode = cipher_mode_type()) :
                    result(), value_array(), c(mode), seen() {
                }

                stream_preprocessor(const cipher_type &cipher = cipher_type(),
                                    const cipher_padding_type &padding = cipher_padding_type()) :
                    result(),
                    value_array(), c(cipher, padding), seen() {
                }

                void reset() {
                    seen = 0;
                    result.clear();
                    c.reset();
                }

            private:
                digest_type result;
                value_array_type value_array;
                cipher<cipher_type, cipher_mode_type, cipher_padding_type> c;
                length_type seen;
            };
        }    // namespace pubkey
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_PUBKEY_STREAM_PREPROCESSOR_HPP
