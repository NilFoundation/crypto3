//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP
#define BOOST_MULTIPRECISION_MONTGOMERY_PARAMS_HPP

#include <boost/container/vector.hpp>

#include <boost/type_traits/is_integral.hpp>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_int/cpp_int_config.hpp>
#include <boost/multiprecision/modular/base_params.hpp>
#include <boost/multiprecision/modular/barrett_params.hpp>

#include <type_traits>
#include <array>
#include <cstddef> // std::size_t
#include <limits>
#include <string>

namespace boost {
namespace multiprecision {
namespace backends {

    template <size_t N, typename T = uint64_t, typename = std::enable_if_t<std::is_integral<T>::value>>
    struct big_int : std::array<T, N> {};

    namespace detail
    {
        template<unsigned... digits>
        struct to_chars { static const char value[]; };

        template<unsigned... digits>
        const char to_chars<digits...>::value[] = {('0' + digits)..., 0};

        template<unsigned rem, unsigned... digits>
        struct explode : explode<rem / 10, rem % 10, digits...> {};

        template<unsigned... digits>
        struct explode<0, digits...> : to_chars<digits...> {};
    }

    template<unsigned num>
    struct num_to_string : detail::explode<num / 10, num % 10> {};

    namespace cbn {

        template <typename T> struct dbl_bitlen { using type = void; };
        template <> struct dbl_bitlen<uint8_t> { using type = uint16_t; };
        template <> struct dbl_bitlen<uint16_t> { using type = uint32_t; };
        template <> struct dbl_bitlen<uint32_t> { using type = uint64_t; };
        template <> struct dbl_bitlen<uint64_t> { using type = __uint128_t; };
        //template <> struct dbl_bitlen<unsigned long> { using type = __uint128_t; };

        template <typename T = uint64_t, T... Limbs, std::size_t... Is>
        constexpr auto take_first(std::integer_sequence<T, Limbs...>,
                                  std::index_sequence<Is...>) {
            constexpr big_int<sizeof...(Limbs), T> num = {Limbs...};
            return std::integer_sequence<T, num[Is]...>{};
        }

        template <size_t ResultLength, typename T, size_t N1>
        constexpr auto take(big_int< N1, T> t, const size_t Begin, const size_t End, const size_t Offset = 0) {

            big_int< ResultLength, T> res{};
            for (auto i = Begin; i < End; ++i) {
                res[i-Begin+Offset] = t[i];
            }

            return res;
        }

        template <size_t Begin, size_t End, size_t Padding=0, typename T, size_t N1>
        constexpr auto take(big_int< N1, T> t) {
            //static_assert(End >= Begin, "invalid range");
            //static_assert(End - Begin <= N1, "invalid range");

            big_int< End - Begin + Padding, T> res{};
            for (auto i = Begin; i < End; ++i) {
                res[i-Begin] = t[i];
            }

            return res;
        }


        template <size_t N, typename T, size_t N1>
        constexpr auto first(big_int<N1, T> t)
        {
            // take first N limbs
            // first<N>(x) corresponds with x modulo (2^64)^N
            return take<0, N>(t);
        }

        template <typename T, size_t N1>
        constexpr auto first(big_int<N1, T> t, size_t N)
        {
            // take first N limbs, runtime version
            // first(x,N) corresponds with x modulo (2^64)^N
            return take<N1>(t, 0, N);
        }

        template <size_t N, typename T, size_t N1>
        constexpr auto pad(big_int<N1, T> t) {
            // add N extra limbs (at msb side)
            return take<0, N1, N>(t);
        }

        template <size_t ExplicitLength = 0, typename T, T... Limbs>
        constexpr auto to_big_int(std::integer_sequence<T, Limbs...>) {
            return big_int<ExplicitLength ? ExplicitLength : sizeof...(Limbs),T>{ Limbs... };
        }

        template <size_t N, typename T>
        constexpr auto tight_length(big_int<N, T> num) {
            // count the effective number of limbs
            // (ignoring zero-limbs at the most-significant-limb side)
            size_t L = N;
            while (L > 0 && num[L - 1] == 0)
                --L;

            return L;
        }

        template <typename T, T... Is>
        constexpr auto tight_length(std::integer_sequence<T, Is...>)
        {
            // count the effective number of limbs
            // (ignoring zero-limbs at the most-significant-limb side)

            size_t L = sizeof...(Is);
            std::array<T, sizeof...(Is)> num{Is...};
            while (L > 0 && num[L - 1] == 0)
                --L;

            return L;
        }

        template <typename T, size_t N>
        //CBN_ALWAYS_INLINE
        constexpr auto add_ignore_carry(big_int<N, T> a, big_int<N, T> b) {
            T carry{};
            big_int<N, T> r{};

            for (auto i = 0; i < N; ++i) {
                T aa = a[i];
                T sum = aa + b[i];
                T res = sum + carry;
                carry = (sum < aa) | (res < sum);
                r[i] = res;
            }

            return r;
        }

        template <size_t ResultLength, size_t M, size_t N, typename T>
        constexpr auto partial_mul(big_int<M, T> u, big_int<N, T> v) {

            using TT = typename cbn::dbl_bitlen<T>::type;
            big_int<ResultLength, T> w{};
            for (auto j = 0; j < N; ++j) {
                // if (v[j] == 0) {
                //  if (j + M < ResultLength)
                //    w[j + M] = static_cast<T>(0);
                //} else {
                T k = 0;
                const auto m = std::min(M, ResultLength - j);
                for (auto i = 0; i < m; ++i) {
                    TT t = static_cast<TT>(u[i]) * static_cast<TT>(v[j]) + w[i + j] + k;
                    w[i + j] = static_cast<T>(t);
                    k = t >> std::numeric_limits<T>::digits;
                }
                if (j + M < ResultLength)
                    w[j + M] = k;
                //}
            }
            return w;
        }

        template <typename T = uint64_t, size_t L = 0, char... Chars> //, std::size_t... Is>
        constexpr auto chars_to_big_int(std::integer_sequence<char, Chars...>) {
            // might return a 'non-tight' representation, meaning that there could be
            // leading zero-limbs
            constexpr size_t len = sizeof...(Chars);
            constexpr size_t N = std::max(L, 1 + (10 * len) / (3 * std::numeric_limits<T>::digits));
            std::array<char, len> digits{Chars...};
            big_int<N, T> num{0};
            big_int<N, T> power_of_ten{1};

            for (int i = len - 1; i >= 0; --i) {
                num = add_ignore_carry(num, partial_mul<N>(big_int<1, T>{static_cast<T>(digits[i]) - 48}, power_of_ten));
                power_of_ten = partial_mul<N>(big_int<1, T>{static_cast<T>(10)}, power_of_ten);
            }
            return num;
        }

        template <typename T = uint64_t, char... Chars, std::size_t... Is>
        constexpr auto chars_to_integer_seq(std::integer_sequence<char, Chars...>,
                                            std::index_sequence<Is...>) {
            constexpr auto num = chars_to_big_int<T, sizeof...(Chars)>(std::integer_sequence<char, Chars...>{});
            return std::integer_sequence<T, num[Is]...>{};
        }

        template <char... Chars> constexpr auto operator "" _Z() {

            using T = uint64_t; // Question: How to elegantly expose the choice of this
            // type to the user?

            constexpr size_t len = sizeof...(Chars);
            constexpr size_t N = 1 + (10 * len) / (3 * std::numeric_limits<T>::digits);

            auto num = chars_to_integer_seq(std::integer_sequence<char, Chars...>{}, std::make_index_sequence<N>{});
            constexpr auto L = tight_length(num) + (to_big_int(num) == big_int<1, T>{});
            return take_first(num, std::make_index_sequence<L>{});
        }

        template <typename T, size_t N>
        //CBN_ALWAYS_INLINE
        constexpr auto subtract_same(big_int<N, T> a, big_int<N, T> b)
        {
            T carry{};
            big_int<N + 1, T> r{};

            for (auto i = 0; i < N; ++i) {
                auto aa = a[i];
                auto diff = aa - b[i];
                auto res = diff - carry;
                carry = (diff > aa) | (res > diff);
                r[i] = res;
            }

            r[N] = carry * static_cast<T>(-1); // sign extension
            return r;
        }

        template <typename T, size_t M, size_t N>
        //CBN_ALWAYS_INLINE
        constexpr auto subtract(big_int<M, T> a, big_int<N, T> b)
        {
            constexpr auto L = std::max(M, N);
            return subtract_same(cbn::pad<L - M>(a), cbn::pad<L - N>(b));
        }


        template <size_t N, typename T>
        constexpr bool equal(big_int<N, T> a, big_int<N, T> b) {
            size_t x = 0;
            for (auto i = 0; i < N; ++i)
                x += (a[i] != b[i]);
            return (x == 0);
        }

        template <typename T, size_t N1, size_t N2>
        constexpr bool operator==(big_int<N1, T> a, big_int<N2, T> b) {
            constexpr auto L = std::max(N1, N2);
            return equal(pad<L - N1>(a), pad<L - N2>(b));
        }

        template <size_t N, typename T>
        constexpr bool less_than(big_int<N, T> a, big_int<N, T> b) {

            return subtract(a, b)[N];
        }

        template <typename T, size_t N1, size_t N2>
        constexpr bool operator<(big_int<N1, T> a, big_int<N2, T> b) {
            constexpr auto L = std::max(N1, N2);
            return less_than(pad<L - N1>(a), pad<L - N2>(b));
        }

        template <typename T, size_t N1, size_t N2>
        constexpr bool operator>=(big_int<N1, T> a, big_int<N2, T> b) {
            return  !(a < b);
        }

        template <typename T, size_t N1, size_t N2>
        constexpr auto operator-(big_int<N1, T> a, big_int<N2, T> b) {
            return subtract(a, b);
        }

        template <char... Chars> constexpr auto convert_to() {

            using T = uint64_t; // Question: How to elegantly expose the choice of this
            // type to the user?

            constexpr size_t len = sizeof...(Chars);
            constexpr size_t N = 1 + (10 * len) / (3 * std::numeric_limits<T>::digits);

            auto num = chars_to_integer_seq(std::integer_sequence<char, Chars...>{}, std::make_index_sequence<N>{});
            constexpr auto L = tight_length(num) + (to_big_int(num) == big_int<1, T>{});
            return take_first(num, std::make_index_sequence<L>{});
        }

        template <size_t K, size_t N, typename T = uint64_t>
        constexpr auto unary_encoding() {
            // N limbs, Kth limb set to one
            big_int<N, T> res{};
            res[K] = 1;
            return res;
        }

        template <size_t N, typename T = uint64_t>
        constexpr auto unary_encoding(size_t K)
        {
            big_int<N, T> res{};
            res[K] = 1;
            return res;
        }

        template <size_t N, typename T>
        constexpr auto shift_right(big_int<N, T> a, size_t k)
        {
            // shift-right the big integer a by k bits
            big_int<N, T> res{};

            if (k == 0) return a;

            for (auto i = 0; i < N - 1; ++i) {
                res[i] = (a[i] >> k) | (a[i + 1] << (std::numeric_limits<T>::digits - k));
            }
            res[N - 1] = (a[N - 1] >> k);
            return res;
        }

        template <size_t N, typename T>
        constexpr auto shift_left(big_int<N, T> a, size_t k)
        {
            // shift-left the big integer a by k bits
            // answer has 1 limb more
            //

            if (k == 0) return pad<1>(a);

            big_int<N + 1, T> res{};

            res[0] = (a[0] << k);

            for (auto i = 1; i < N; ++i) {
                res[i] = (a[i] << k) | (a[i - 1] >> (std::numeric_limits<T>::digits - k));
            }

            res[N] = a[N - 1] >> (std::numeric_limits<T>::digits - k);
            return res;
        }

        template <size_t N, size_t Padding = 0, typename T, size_t N1>
        constexpr auto skip(big_int<N1, T> t)
        {
            // skip first N limbs
            // skip<N>(x) corresponds with right-shifting x by N limbs
            return cbn::take<N, N1, Padding>(t);
        }

        template <typename T, size_t N1>
        constexpr auto skip(big_int<N1, T> t, size_t N)
        {
            // skip first N limbs, runtime version
            // skip<N>(x) corresponds with right-shifting x by N limbs
            return cbn::take<N1>(t, N, N1);
        }

        template <typename T, std::size_t N>
        //CBN_ALWAYS_INLINE
        constexpr auto short_mul(big_int<N, T> a, T b) {

            using TT = typename cbn::dbl_bitlen<T>::type;
            big_int<N + 1, T> p{};
            T k = 0;
            for (auto j = 0; j < N; ++j) {
                TT t = static_cast<TT>(a[j]) * static_cast<TT>(b) + k;
                p[j] = t;
                k = t >> std::numeric_limits<T>::digits;
            }
            p[N] = k;
            return p;
        }


        template <size_t padding_limbs = 0, size_t M, size_t N, typename T>
        //CBN_ALWAYS_INLINE
        constexpr auto mul(big_int<M, T> u, big_int<N, T> v)
        {

            using TT = typename cbn::dbl_bitlen<T>::type;
            big_int<M + N + padding_limbs, T> w{};
            for (auto j = 0; j < N; ++j) {
                // if (v[j] == 0)
                //  w[j + M] = static_cast<uint64_t>(0);
                // else {
                T k = 0;
                for (auto i = 0; i < M; ++i) {
                    TT t = static_cast<TT>(u[i]) * static_cast<TT>(v[j]) + w[i + j] + k;
                    w[i + j] = static_cast<T>(t);
                    k = t >> std::numeric_limits<T>::digits;
                }
                w[j + M] = k;
                //}
            }
            return w;
        }

        template <typename T, size_t N1, size_t N2>
        constexpr auto join(big_int< N1, T> a, big_int< N2, T> b) {
            big_int< N1+N2, T> result {};

            for (auto i = 0; i<N1; ++i)
                result[i] = a[i];

            for (auto i = 0; i<N2; ++i)
                result[N1+i] = b[i];

            return result;
        }

        template <typename T, size_t N>
        constexpr auto subtract_ignore_carry(big_int<N, T> a, big_int<N, T> b)
        {
            T carry{};
            big_int<N, T> r{};

            for (auto i = 0; i < N; ++i) {
                auto aa = a[i];
                auto diff = aa - b[i];
                auto res = diff - carry;
                carry = (diff > aa) | (res > diff);
                r[i] = res;
            }

            return r;
        }

        template <typename Q, typename R> struct DivisionResult {
            Q quotient;
            R remainder;
        };

        template <size_t M, typename T> constexpr
        DivisionResult<big_int<M, T>,big_int<1, T>>
        short_div(big_int<M, T> u, T v) {
            using TT = typename cbn::dbl_bitlen<T>::type;
            TT r{0};
            big_int<M, T> q{};
            for (int i = M - 1; i >= 0; --i) {
                TT w = (r << std::numeric_limits<T>::digits) + u[i];
                q[i] = w / v;
                r = w % v;
            }
            return {q, {static_cast<T>(r)}};
        }

        template <size_t M, size_t N, typename T>
        constexpr DivisionResult<big_int<M, T>, big_int<N, T>> div(big_int<M, T> u,
                                                                   big_int<N, T> v)
        {
            // Knuth's "Algorithm D" for multiprecision division as described in TAOCP
            // Volume 2: Seminumerical Algorithms
            // combined with short division

            //
            // input:
            // u  big_int<M>,      M>=N
            // v  big_int<N>
            //
            // computes:
            // quotient = floor[ u/v ]
            // rem = u % v
            //
            // returns:
            // std::pair<big_int<N+M>, big_int<N>>(quotient, rem)

            using TT = typename cbn::dbl_bitlen<T>::type;
            size_t tight_N = N;
            while (tight_N > 0 && v[tight_N - 1] == 0)
                --tight_N;

            big_int<M, T> q{};

            if (tight_N == 1) { // short division
                TT r {};
                for (int i = M - 1; i >= 0; --i) {
                    TT w = (r << std::numeric_limits<T>::digits) + u[i];
                    q[i] = w / v[0];
                    r = w % v[0];
                }
                return {q, {static_cast<T>(r)}};
            }

            uint8_t k = 0;
            while (v[tight_N - 1] <
                   (static_cast<T>(1) << (std::numeric_limits<T>::digits - 1))) {
                ++k;
                v = first<N>(shift_left(v, 1));
            }
            auto us = shift_left(u, k);

            for (int j = M - tight_N; j >= 0; --j) {
                TT tmp = us[j + tight_N - 1];
                TT tmp2 = us[j + tight_N];
                tmp += (tmp2 << std::numeric_limits<T>::digits);
                TT qhat = tmp / v[tight_N - 1];
                TT rhat = tmp % v[tight_N - 1];

                auto b = static_cast<TT>(1) << std::numeric_limits<T>::digits;
                while (qhat == b ||
                       (qhat * v[tight_N - 2] >
                        (rhat << std::numeric_limits<T>::digits) + us[j + tight_N - 2])) {
                    qhat -= 1;
                    rhat += v[tight_N - 1];
                    if (rhat >= b)
                        break;
                }
                auto true_value = subtract(take<N + 1>(us, j, j + tight_N + 1),
                                           mul(v, big_int<1, T>{{static_cast<T>(qhat)}}));
                if (true_value[tight_N]) {
                    auto corrected =
                            add_ignore_carry(true_value, unary_encoding<N + 2, T>(tight_N + 1));
                    auto new_us_part = add_ignore_carry(corrected, pad<2>(v));
                    for (auto i = 0; i <= tight_N; ++i)
                        us[j + i] = new_us_part[i];
                    --qhat;
                } else {
                    for (auto i = 0; i <= tight_N; ++i)
                        us[j + i] = true_value[i];
                }
                q[j] = qhat;
            }
            return {q, shift_right(first<N>(us), k) };
        }

        template <typename T, T... A, T... B, T... Is, std::size_t N = sizeof...(Is)>
        constexpr auto ext_gcd_impl(std::integer_sequence<T, A...>,
                                    std::integer_sequence<T, B...>,
                                    std::integer_sequence<T, Is...>)
        {

            constexpr auto a = big_int<N, T>{A...};
            constexpr auto b = big_int<N, T>{B...};
            constexpr auto dummy = big_int<N, T>{};

            constexpr bool a_equals_zero =
                    std::is_same<std::integer_sequence<T, A...>,
                            std::integer_sequence<T, dummy[Is]...>>::value;
            if
            constexpr(a_equals_zero) return join(
                        b, join(big_int<N, T>{0}, big_int<N, T>{1}));

            else {
                constexpr auto qr = div(b, a); //constexpr auto qr = div(b, a);
                constexpr auto rem = qr.remainder;
                constexpr auto arg1 = pad<N - rem.size()>(rem);

                constexpr auto triple =
                        ext_gcd_impl(std::integer_sequence<T, arg1[Is]...>(),
                                     std::integer_sequence<T, a[Is]...>(),
                                     std::integer_sequence<T, Is...>());

                constexpr auto x = first<N>(triple);
                constexpr auto y = take<N, 2 * N>(triple);
                constexpr auto z = skip<2 * N>(triple);
                constexpr auto qy = partial_mul<N>(qr.quotient, y);

                return join(join(x, subtract_ignore_carry(z, qy)), y);
            }
        }

        template <typename T, T... A, T... B>
        constexpr auto ext_gcd(std::integer_sequence<T, A...>,
                               std::integer_sequence<T, B...>)
        {
            constexpr std::size_t N = std::max(sizeof...(A), sizeof...(B));
            return ext_gcd_impl(std::integer_sequence<T, A...>{},
                                std::integer_sequence<T, B...>{},
                                std::make_integer_sequence<T, N>{});
        }

        template <typename T, T... X, T... Modulus>
        constexpr auto mod_inv(std::integer_sequence<T, X...>, std::integer_sequence<T, Modulus...>)
        {

            constexpr auto triple = ext_gcd(std::integer_sequence<T, X...>{}, std::integer_sequence<T, Modulus...>{});
            constexpr auto N = std::max(sizeof...(X), sizeof...(Modulus));

            if (triple[0] != 1) {
                throw std::runtime_error("modular inverse does not exist");
            } else {
                using namespace detail;
                constexpr auto mod_inverse = take<N, 2 * N>(triple);
                constexpr auto L = tight_length(mod_inverse);
                return first<L>(mod_inverse);
            }
        }

        template <size_t ResultLength, typename T, size_t N1>
        constexpr auto limbwise_shift_left(big_int< N1, T> t, const size_t k) {
            // shift left by k limbs (and produce output of limb-length ResultLength)
            return take<ResultLength>(t, 0, N1, k);
        }

        template <typename T, std::size_t N1, T... Modulus, std::size_t N2 = sizeof...(Modulus)>
        constexpr auto eval_montgomery_reduce_compile_time_big_int(big_int<N1, T> A, std::integer_sequence<T, Modulus...>)
        {
            using std::integer_sequence;
            using namespace cbn;

            constexpr auto m = big_int<N2, T>{Modulus...};
            constexpr auto inv = mod_inv(integer_sequence<T, Modulus...>{},
                                         integer_sequence<T, 0, 1>{}); // m^{-1} mod 2^64
            constexpr T mprime = -inv[0];

            auto accum = pad<1>(A);

            for (auto i = 0; i < N2; ++i) {
                auto prod = short_mul(m, accum[i] * mprime);
                auto prod2 = limbwise_shift_left<N1 + 1>(prod, i);
                accum = add_ignore_carry(accum, prod2);
            }

            auto result = skip<N2>(accum);
            auto padded_mod = pad<1>(m);
            if (result >= padded_mod)
                result = subtract_ignore_carry(result, padded_mod);

            auto tmp = first<N2>(result);

            return tmp;
        }

        template <typename Backend>
        constexpr Backend eval_montgomery_reduce_compile_time_backend(Backend result)
        {
            /*
            auto tmp = num_to_string<result>::value;
            std::cout<<cpp_int(result)<<std::endl;
            std::cout<<result<<std::endl;
             */
              //constexpr auto result_modulus = ;
             // constexpr auto result_base = ;

            //  constexpr auto eval_montgomery_reduce_compile_time_big_int(result_base, result_modulus);

                constexpr auto modulus = 1267650600228229401496703205653_Z;
                constexpr auto T = to_big_int<4>(1532495540865888858358347027150309183618739122183602175_Z);
                constexpr auto ans = to_big_int(730531796855002292035529737298_Z);

                constexpr auto tmp = eval_montgomery_reduce_compile_time_big_int(T, modulus);

                static_assert(eval_montgomery_reduce_compile_time_big_int(T, modulus) == ans, "fail");


            return result;
        }
    }


/**
 * Parameters for Montgomery Reduction
 */
template <typename Backend>
class montgomery_params : public base_params<Backend>
{
   typedef number<Backend> number_type;

 protected:
   template <typename Number>
   constexpr void initialize_montgomery_params(const Number& p)
   {
      this->initialize_base_params(p);
      find_const_variables(p);
   }

   constexpr void initialize_montgomery_params(const montgomery_params<Backend>& p)
   {
      this->initialize_base_params(p);
      find_const_variables(p);
   }

   constexpr limb_type monty_inverse(limb_type a)
   {
      if (a % 2 == 0)
      {
         throw std::invalid_argument("Monty_inverse only valid for odd integers");
      }

      limb_type b = 1;
      limb_type r = 0;

      for (size_t i = 0; i != sizeof(limb_type) * CHAR_BIT; ++i)
      {
         const limb_type bi = b % 2;
         r >>= 1;
         r += bi << (sizeof(limb_type) * CHAR_BIT - 1);

         b -= a * bi;
         b >>= 1;
      }

      // Now invert in addition space
      r = (~static_cast<limb_type>(0) - r) + 1;

      return r;
   }

   template <typename T>
   constexpr void find_const_variables(const T& pp)
   {
      number_type p = pp;
      if (p <= 0 || !(p % 2))
      {
         return;
      }

      m_p_words = this->m_mod.backend().size();

      m_p_dash = monty_inverse(this->m_mod.backend().limbs()[0]);

      number_type r;

      default_ops::eval_bit_set(r.backend(), m_p_words * sizeof(limb_type) * CHAR_BIT);

      m_r2 = r * r;
      barrett_params<Backend> barrettParams(this->m_mod);
      barrettParams.eval_barret_reduce(m_r2.backend());
   }

 public:
   constexpr montgomery_params() : base_params<Backend>(), m_p_dash(), m_p_words() {}

   template <typename Number>
   constexpr explicit montgomery_params(const Number& p) : base_params<Backend>(p), m_p_dash(), m_p_words()
   {
      initialize_montgomery_params(p);
   }

   constexpr const number_type& r2() const { return m_r2; }

   constexpr limb_type p_dash() const { return m_p_dash; }

   constexpr size_t p_words() const { return m_p_words; }

   template <class V>
   constexpr montgomery_params& operator=(const V& v)
   {
      initialize_montgomery_params(v);
      return *this;
   }





    constexpr void eval_montgomery_reduce_compile_time(Backend& result) const
    {
        using namespace cbn;

        result = eval_montgomery_reduce_compile_time_backend(result);

        //result = eval_montgomery_reduce_compile_time_big_int(to_big_int(std::integer_sequence<Backend>(result)), this->m_mod.backend());
    }






    inline void eval_montgomery_reduce_run_time(Backend& result) const
    {
        using default_ops::eval_lt;
        using default_ops::eval_multiply_add;

        typedef cpp_int_backend<sizeof(limb_type) * CHAR_BIT * 3, sizeof(limb_type) * CHAR_BIT * 3, unsigned_magnitude, unchecked, void> cpp_three_int_backend;

        const size_t    p_size = m_p_words;
        const limb_type p_dash = m_p_dash;
        const size_t    z_size = 2 * (p_words() + 1);

        container::vector<limb_type> z(result.size(), 0); //container::vector<limb_type, alloc> z(result.size(), 0);
        for (size_t i = 0; i < result.size(); ++i)
        {
            z[i] = result.limbs()[i];
        }

        if (result.size() < z_size)
        {
            result.resize(z_size, z_size);
            z.resize(z_size, 0);
        }

        cpp_three_int_backend w(z[0]);

        result.limbs()[0] = w.limbs()[0] * p_dash;

        eval_multiply_add(w, result.limbs()[0], this->m_mod.backend().limbs()[0]);
        eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);

        for (size_t i = 1; i != p_size; ++i)
        {
            for (size_t j = 0; j < i; ++j)
            {
                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[i - j]);
            }

            eval_add(w, z[i]);

            result.limbs()[i] = w.limbs()[0] * p_dash;

            eval_multiply_add(w, result.limbs()[i], this->m_mod.backend().limbs()[0]);

            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
        }

        for (size_t i = 0; i != p_size; ++i)
        {
            for (size_t j = i + 1; j != p_size; ++j)
            {
                eval_multiply_add(w, result.limbs()[j], this->m_mod.backend().limbs()[p_size + i - j]);
            }

            eval_add(w, z[p_size + i]);

            result.limbs()[i] = w.limbs()[0];

            eval_right_shift(w, sizeof(limb_type) * CHAR_BIT);
        }

        eval_add(w, z[z_size - 1]);

        result.limbs()[p_size]     = w.limbs()[0];
        result.limbs()[p_size + 1] = w.limbs()[1];

        if (result.size() != p_size + 1)
        {
            result.resize(p_size + 1, p_size + 1);
        }
        result.normalize();
    }

    template <bool c, typename Dummy>
    constexpr typename std::enable_if<!(c && sizeof(Dummy))>::type eval_montgomery_reduce(Backend& result) const
    {
        eval_montgomery_reduce_compile_time(result);
    }

    template <bool c, typename Dummy>
    constexpr typename std::enable_if<c && sizeof(Dummy)>::type eval_montgomery_reduce(Backend& result) const
    {
        eval_montgomery_reduce_run_time(result);
    }


 protected:
   number_type m_r2;
   limb_type   m_p_dash;
   size_t      m_p_words;
};
}
}
} // namespace boost::multiprecision::backends

#endif
