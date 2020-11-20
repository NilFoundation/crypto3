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
#include <tuple>
#include <array>
#include <cstddef> // std::size_t
#include <limits>
#include <string>

namespace boost {
namespace multiprecision {
namespace backends {

namespace cbn {
/// Warning: the function doesn't check arguments due to constexpr implementation restrictions,
///          so should be used accurately
template<std::size_t BeginLimb, std::size_t EndLimb, std::size_t Padding = 0,
         unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto take(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &t) {
   using backend_type = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   using result_type = cpp_int_backend<(EndLimb - BeginLimb + Padding) * backend_type::limb_bits,
                                       (EndLimb - BeginLimb + Padding) * backend_type::limb_bits,
                                       SignType, Checked, void>;

   result_type res;
   for (auto i = BeginLimb; i < EndLimb; ++i) {
      res.limbs()[i- BeginLimb] = t.limbs()[i];
   }

   return res;
}

/// Warning: the function doesn't check arguments due to constexpr implementation restrictions,
///          so should be used accurately
template<unsigned ResultMinBits, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto take(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &t,
                    const std::size_t Begin, const std::size_t End, const std::size_t Offset = 0) {
   using result_type = cpp_int_backend<ResultMinBits, ResultMinBits, SignType, Checked, void>;

   result_type res;
   for (auto i = Begin; i < End; ++i) {
      res.limbs()[i-Begin+Offset] = t.limbs()[i];
   }

   return res;
}

/// Warning: the function doesn't check arguments due to constexpr implementation restrictions,
///          so should be used accurately
template <size_t N, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto first(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &t) {
   // take first N limbs
   // first<N>(x) corresponds with x modulo (2^64)^N
   return take<0, N>(t);
}

/// Warning: the function works with a real size (internal_limb_count) of a fixed precision cpp_int_backend
///          and doesn't affect/depend on a logical size (m_limbs), so should be used accurately
template<std::size_t N, std::size_t Padding = 0,
         unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto skip(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &t)
{
   using backend_type = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   
   // skip first N limbs
   // skip<N>(x) corresponds with right-shifting x by N limbs
   return take<N, backend_type::internal_limb_count, Padding>(t);
}

/// Warning: the function doesn't check arguments due to constexpr implementation restrictions,
///          so should be used accurately
template <unsigned ResultMinBits, unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto limbwise_shift_left(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &t,
                                   const std::size_t k) {
   // shift left by k limbs (and produce output of limb-length ResultLength)
   return take<ResultMinBits>(t, 0, t.size(), k);
}

/// Warning: the function works with real size (internal_limb_count) of fixed precision cpp_int_backend
///          and doesn't affect/depend on logical size (m_limbs)
template <unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto add_ignore_carry(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &a,
                                const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &b) {
   using backend_type = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;

   limb_type carry = 0;
   backend_type r;

   for (auto i = 0; i < backend_type::internal_limb_count; ++i) {
      limb_type aa  = a.limbs()[i];
      limb_type sum = aa + b.limbs()[i];
      limb_type res = sum + carry;
      carry = (sum < aa) | (res < sum);
      r.limbs()[i]  = res;
   }

   return r;
}

/// Warning: the function works with a real size (internal_limb_count) of a fixed precision cpp_int_backend
///          and doesn't affect/depend on a logical size (m_limbs), so should be used accurately
template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto subtract_ignore_carry(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &a,
                                     const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &b) {
   using backend_type = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   
   limb_type carry = 0;
   backend_type r;

   for (auto i = 0; i < backend_type::internal_limb_count; ++i)
   {
      limb_type aa = a.limbs()[i];
      limb_type diff = aa - b.limbs()[i];
      limb_type res = diff - carry;
      carry = (diff > aa) | (res > diff);
      r.limbs()[i] = res;
   }

   return r;
}

/// Warning: the function works with a real size (internal_limb_count) of a fixed precision cpp_int_backend
///          and doesn't affect/depend on a logical size (m_limbs), so should be used accurately
template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
constexpr auto short_mul(const cpp_int_backend<MinBits, MinBits, SignType, Checked, void> &a, limb_type b) {
   using backend_type = cpp_int_backend<MinBits, MinBits, SignType, Checked, void>;
   using result_type = cpp_int_backend<MinBits + backend_type::limb_bits,
       MinBits + backend_type::limb_bits,
       SignType, Checked, void>;

   result_type p;
   limb_type k = 0;
   for (auto j = 0; j < backend_type::internal_limb_count; ++j) {
      double_limb_type t = static_cast<double_limb_type>(a.limbs()[j]) * static_cast<double_limb_type>(b) + k;
      p.limbs()[j] = t;
      k = t >> backend_type::limb_bits;
   }
   p.limbs()[a.size()] = k;
   return p;
}
} // namespace cbn

/**
 * Parameters for Montgomery Reduction
 */
template <typename Backend>
class montgomery_params : public base_params<Backend>
{
   typedef number<Backend> number_type;

 protected:
   template <typename Number>
   inline void initialize_montgomery_params(const Number& p)
   {
      this->initialize_base_params(p);
      find_const_variables(p);
   }

   inline void initialize_montgomery_params(const montgomery_params<Backend>& p)
   {
      this->initialize_base_params(p);
      find_const_variables(p);
   }

   limb_type monty_inverse(limb_type a)
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
   void find_const_variables(const T& pp)
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
   montgomery_params() : base_params<Backend>() {}

   template <typename Number>
   explicit montgomery_params(const Number& p) : base_params<Backend>(p)
   {
      initialize_montgomery_params(p);
   }

   inline const number_type& r2() const { return m_r2; }

   inline limb_type p_dash() const { return m_p_dash; }

   inline size_t p_words() const { return m_p_words; }

   template <class V>
   montgomery_params& operator=(const V& v)
   {
      initialize_montgomery_params(v);
      return *this;
   }

   inline void eval_montgomery_reduce(Backend& result) const
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

 protected:
   number_type m_r2;
   limb_type   m_p_dash;
   size_t      m_p_words;
};

// fixed precision montgomery params type which supports compile-time execution
template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
class montgomery_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>> :
    public base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
{
   static_assert(MinBits, "number of bits should be defined");
   typedef cpp_int_backend<MinBits, MinBits, SignType, Checked, void> Backend;
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

   constexpr void eval_montgomery_reduce(Backend& result) const
   {
      using namespace cbn;
      using padded_backend_type = cpp_int_backend<MinBits + Backend::limb_bits,
                                                  MinBits + Backend::limb_bits,
                                                  SignType, Checked, void>;
      using dbl_backend_type = cpp_int_backend<2 * MinBits, 2 * MinBits, SignType, Checked, void>;
      using padded_dbl_backend_type = cpp_int_backend<2 * MinBits + Backend::limb_bits,
                                                      2 * MinBits + Backend::limb_bits,
                                                      SignType, Checked, void>;

      padded_dbl_backend_type accum(result);

      for (auto i = 0; i < this->m_mod.backend().size(); ++i)
      {
         padded_backend_type prod = short_mul(this->m_mod.backend(), accum.limbs()[i] * p_dash());
         padded_dbl_backend_type prod2 = limbwise_shift_left<2 * MinBits + Backend::limb_bits>(prod, i);
         accum = add_ignore_carry(accum, prod2);
      }

      padded_backend_type inner_result = skip<Backend::internal_limb_count>(accum);

      padded_backend_type padded_mod(this->m_mod.backend());
      if (inner_result.compare(padded_mod) >= 0)
      {
         inner_result = subtract_ignore_carry(inner_result, padded_mod);
      }

      result = first<Backend::internal_limb_count>(inner_result);
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
