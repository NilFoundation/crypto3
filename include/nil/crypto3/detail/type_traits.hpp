//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_TYPE_TRAITS_HPP
#define CRYPTO3_TYPE_TRAITS_HPP

#define GENERATE_HAS_MEMBER_TYPE(Type)                                                \
                                                                                      \
    template<class T>                                                                 \
    class HasMemberType_##Type {                                                      \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            struct Type { };                                                          \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(typename U::Type *);                                          \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##Type : public std::integral_constant<bool, HasMemberType_##Type<T>::RESULT> { };

#define GENERATE_HAS_MEMBER(member)                                                   \
                                                                                      \
    template<class T>                                                                 \
    class HasMember_##member {                                                        \
    private:                                                                          \
        using Yes = char[2];                                                          \
        using No = char[1];                                                           \
                                                                                      \
        struct Fallback {                                                             \
            int member;                                                               \
        };                                                                            \
        struct Derived : T, Fallback { };                                             \
                                                                                      \
        template<class U>                                                             \
        static No &test(decltype(U::member) *);                                       \
        template<typename U>                                                          \
        static Yes &test(U *);                                                        \
                                                                                      \
    public:                                                                           \
        static constexpr bool RESULT = sizeof(test<Derived>(nullptr)) == sizeof(Yes); \
    };                                                                                \
                                                                                      \
    template<class T>                                                                 \
    struct has_##member : public std::integral_constant<bool, HasMember_##member<T>::RESULT> { };

namespace nil {
    namespace crypto3 {
        namespace detail {
            GENERATE_HAS_MEMBER_TYPE(const_iterator)

            GENERATE_HAS_MEMBER_TYPE(encoded_value_type)
            GENERATE_HAS_MEMBER_TYPE(encoded_block_type)
            GENERATE_HAS_MEMBER_TYPE(decoded_value_type)
            GENERATE_HAS_MEMBER_TYPE(decoded_block_type)

            GENERATE_HAS_MEMBER_TYPE(block_type)
            GENERATE_HAS_MEMBER_TYPE(digest_type)
            GENERATE_HAS_MEMBER_TYPE(key_type)
            GENERATE_HAS_MEMBER_TYPE(key_schedule_type)
            GENERATE_HAS_MEMBER_TYPE(word_type)

            GENERATE_HAS_MEMBER(encoded_value_bits)
            GENERATE_HAS_MEMBER(encoded_block_bits)
            GENERATE_HAS_MEMBER(decoded_value_bits)
            GENERATE_HAS_MEMBER(decoded_block_bits)

            GENERATE_HAS_MEMBER(block_bits)
            GENERATE_HAS_MEMBER(digest_bits)
            GENERATE_HAS_MEMBER(key_bits)
            GENERATE_HAS_MEMBER(key_schedule_bits)
            GENERATE_HAS_MEMBER(word_bits)

            GENERATE_HAS_MEMBER(rounds)

            template<typename T>
            struct is_iterator {
                static char test(...);

                template<typename U, typename = typename std::iterator_traits<U>::difference_type,
                         typename = typename std::iterator_traits<U>::pointer,
                         typename = typename std::iterator_traits<U>::reference,
                         typename = typename std::iterator_traits<U>::value_type,
                         typename = typename std::iterator_traits<U>::iterator_category>
                static long test(U &&);

                constexpr static bool value = std::is_same<decltype(test(std::declval<T>())), long>::value;
            };

            template<typename Container>
            struct is_container {
            private:
                template<typename T>
                struct has_begin_end {
                    struct Dummy {
                        typedef void const_iterator;
                    };
                    typedef typename std::conditional<has_const_iterator<T>::value, T, Dummy>::type TType;
                    typedef typename TType::const_iterator iter;

                    struct Fallback {
                        iter begin() const;

                        iter end() const;
                    };

                    struct Derived : TType, Fallback { };

                    template<typename C, C>
                    struct ChT;

                    template<typename C>
                    static char (&f(ChT<iter (Fallback::*)() const, &C::begin> *))[1];

                    template<typename C>
                    static char (&f(...))[2];

                    template<typename C>
                    static char (&g(ChT<iter (Fallback::*)() const, &C::end> *))[1];

                    template<typename C>
                    static char (&g(...))[2];

                    static bool const beg_value = sizeof(f<Derived>(0)) == 2;
                    static bool const end_value = sizeof(g<Derived>(0)) == 2;
                };

            public:
                static const bool value = has_const_iterator<Container>::value && has_begin_end<Container>::beg_value &&
                                          has_begin_end<Container>::end_value;
            };

            template<typename T>
            struct is_codec {
                static const bool value = has_encoded_value_type<T>::value && has_encoded_value_bits<T>::value &&
                                          has_decoded_value_type<T>::value && has_decoded_value_bits<T>::value &&
                                          has_encoded_block_type<T>::value && has_encoded_block_bits<T>::value &&
                                          has_decoded_block_type<T>::value && has_decoded_block_bits<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_block_cipher {
                static const bool value = has_word_type<T>::value && has_word_bits<T>::value &&
                                          has_block_type<T>::value && has_block_bits<T>::value &&
                                          has_key_type<T>::value && has_key_bits<T>::value && has_rounds<T>::value;
                typedef T type;
            };

            template<typename T>
            struct is_hash {
            private:
                typedef char one;
                typedef struct {
                    char array[2];
                } two;

                template<typename C>
                static one test_construction_type(typename C::construction::type *);

                template<typename C>
                static two test_construction_type(...);

                template<typename C>
                static one test_construction_params(typename C::construction::params_type *);

                template<typename C>
                static two test_construction_params(...);

            public:
                static const bool value = has_digest_type<T>::value && has_digest_bits<T>::value &&
                                          sizeof(test_construction_type<T>(0)) == sizeof(one) &&
                                          sizeof(test_construction_params<T>(0)) == sizeof(one);
                typedef T type;
            };

            template<typename T>
            struct is_mac {
                static const bool value = has_digest_type<T>::value && has_digest_bits<T>::value &&
                                          has_block_type<T>::value && has_block_bits<T>::value &&
                                          has_key_type<T>::value && has_key_bits<T>::value;
                typedef T type;
            };
        }    // namespace detail
    }        // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_CODEC_TYPE_TRAITS_HPP
