//---------------------------------------------------------------------------//
// Copyright (c) 2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2019 Alexey Moskvin
// Copyright (c) 2020 Ilias Khairullin <ilias@nil.foundation>
//
// Distributed under the Boost Software License, Version 1.0
// See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt
//---------------------------------------------------------------------------//

#ifndef BOOST_MULTIPRECISION_BARRETT_PARAMS_HPP
#define BOOST_MULTIPRECISION_BARRETT_PARAMS_HPP

#include <nil/crypto3/multiprecision/modular/base_params.hpp>

namespace nil {
    namespace crypto3 {
        namespace multiprecision {
            namespace backends {
                /**
                 * Parameters for Montgomery Reduction
                 */
                template<typename Backend>
                class barrett_params : public base_params<Backend> {
                    typedef number<Backend> number_type;

                protected:
                    template<typename Number>
                    inline void initialize_barrett_params(const Number& p) {
                        using default_ops::eval_bit_set;
                        using default_ops::eval_divide;

                        this->initialize_base_params(p);

                        m_mu = 0;

                        eval_bit_set(m_mu.backend(), 2 * (1 + msb(p)));
                        eval_divide(m_mu.backend(), this->m_mod.backend());
                    }

                public:
                    barrett_params() : base_params<Backend>() {
                    }

                    template<typename Number>
                    explicit barrett_params(const Number& p) : base_params<Backend>(p) {
                        initialize_barrett_params(p);
                    }

                    inline const number_type& mu() const {
                        return m_mu;
                    }

                    template<class V>
                    barrett_params& operator=(const V& v) {
                        initialize_barrett_params(v);
                        return *this;
                    }

                    inline void barret_reduce(Backend& result) const {
                        using default_ops::eval_add;
                        using default_ops::eval_bit_set;
                        using default_ops::eval_decrement;
                        using default_ops::eval_lt;
                        using default_ops::eval_msb;
                        using default_ops::eval_multiply;
                        using default_ops::eval_subtract;

                        if (eval_lt(result, this->m_mod.backend())) {
                            if (eval_lt(result, 0ul)) {
                                eval_add(result, this->m_mod.backend());
                                return;
                            }
                            return;
                        } else if (eval_msb(result) < 2 * msb(this->m_mod)) {
                            Backend t1(result);

                            eval_multiply(t1, m_mu.backend());
                            eval_right_shift(t1, 2 * (1 + msb(this->mod())));
                            eval_multiply(t1, this->m_mod.backend());
                            eval_subtract(result, result, t1);

                            if (eval_lt(this->m_mod.backend(), result) ||
                                (result.compare(this->m_mod.backend()) == 0)) {
                                eval_subtract(result, result, this->m_mod.backend());
                            }

                            return;
                        } else {
                            eval_modulus(result, this->m_mod.backend());
                            return;
                        }
                    }

                protected:
                    number_type m_mu;
                };

                // // fixed precision barrett params type which supports compile-time execution
                // template<unsigned MinBits, cpp_integer_type SignType, cpp_int_check_type Checked>
                // class barrett_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
                //     : public base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>>
                // {
                //    typedef base_params<cpp_int_backend<MinBits, MinBits, SignType, Checked, void>> base_type;
                //    typedef typename base_type::policy_type policy_type;
                //
                //    typedef typename policy_type::Backend Backend;
                //    typedef typename policy_type::number_type number_type;
                //    typedef typename policy_type::dbl_lmb_number_type dbl_lmb_number_type;
                //
                //  protected:
                //    constexpr void initialize_barrett_params(const number_type& p)
                //    {
                //       using default_ops::eval_bit_set;
                //       using default_ops::eval_divide;
                //
                //       this->initialize_base_params(p);
                //
                //       m_mu = 0;
                //
                //       eval_bit_set(m_mu.backend(), 2 * (1 + msb(p)));
                //       eval_divide(m_mu.backend(), this->m_mod.backend());
                //    }
                //
                //  public:
                //    constexpr barrett_params() : base_type() {}
                //
                //    constexpr explicit barrett_params(const number_type& p) : base_type(p)
                //    {
                //       initialize_barrett_params(p);
                //    }
                //
                //    constexpr const auto& mu() const { return m_mu; }
                //
                //    template <class V>
                //    constexpr barrett_params& operator=(const V& v)
                //    {
                //       initialize_barrett_params(v);
                //       return *this;
                //    }
                //
                //    template<typename BackendT>
                //    constexpr void barret_reduce(BackendT& result) const
                //    {
                //       using default_ops::eval_add;
                //       using default_ops::eval_bit_set;
                //       using default_ops::eval_decrement;
                //       using default_ops::eval_lt;
                //       using default_ops::eval_multiply;
                //       using default_ops::eval_subtract;
                //       using default_ops::eval_msb;
                //
                //       if (eval_lt(result, this->m_mod.backend()))
                //       {
                //          if (eval_lt(result, 0))
                //          {
                //             eval_add(result, this->m_mod.backend());
                //             return;
                //          }
                //          return;
                //       }
                //       else if (eval_msb(result) < 2 * msb(this->m_mod))
                //       {
                //          Backend t1(result);
                //
                //          eval_multiply(t1, m_mu.backend());
                //          eval_right_shift(t1, 2 * (1 + msb(this->mod())));
                //          eval_multiply(t1, this->m_mod.backend());
                //          eval_subtract(result, result, t1);
                //
                //          if (eval_lt(this->m_mod.backend(), result) || (result.compare(this->m_mod.backend()) == 0))
                //          {
                //             eval_subtract(result, result, this->m_mod.backend());
                //          }
                //
                //          return;
                //       }
                //       else
                //       {
                //          eval_modulus(result, this->m_mod.backend());
                //          return;
                //       }
                //    }
                //
                //  protected:
                //    dbl_lmb_number_type m_mu;
                // };

                // template <typename Backend>
                // class barrett_params : public base_params<Backend>
                //{
                //   typedef number<Backend> number_type;
                //
                // protected:
                //   template <typename Number>
                //   void initialize_barrett_params(const Number& p)
                //   {
                //      using default_ops::eval_bit_set;
                //      using default_ops::eval_divide;
                //
                //      this->initialize_base_params(p);
                //
                //      m_mu = 0;
                //
                //      eval_bit_set(m_mu.backend(), 2 * sizeof(limb_type) * CHAR_BIT * p.backend().size());
                //      eval_divide(m_mu.backend(), this->m_mod.backend());
                //   }
                //
                // public:
                //   barrett_params() : base_params<Backend>() {}
                //
                //   template <typename Number>
                //   explicit barrett_params(const Number& p) : base_params<Backend>(p)
                //   {
                //      initialize_barrett_params(p);
                //   }
                //
                //   const number_type& mu() const { return m_mu; }
                //
                //   template <class V>
                //   barrett_params& operator=(const V& v)
                //   {
                //      initialize_barrett_params(v);
                //      return *this;
                //   }
                //
                //   inline void barret_reduce(Backend& result) const
                //   {
                //      using default_ops::eval_add;
                //      using default_ops::eval_bit_set;
                //      using default_ops::eval_lt;
                //      using default_ops::eval_multiply;
                //      using default_ops::eval_decrement;
                //      using default_ops::eval_subtract;
                //
                //      if (result.size() < this->m_mod.backend().size() || eval_lt(result, this->m_mod.backend()))
                //      {
                //         if (eval_lt(result, 0))
                //         {
                //            eval_add(result, this->m_mod.backend());
                //            return;
                //         }
                //         return;
                //      }
                //      else if (result.size() < 2 * this->m_mod.backend().size())
                //      {
                //         Backend t1(result);
                //
                //         eval_multiply(t1, m_mu.backend());
                //         eval_right_shift(t1, (2 * sizeof(limb_type) * CHAR_BIT * (this->m_mod.backend().size())));
                //
                //         eval_multiply(t1, this->m_mod.backend());
                //
                //         {
                //            Backend tmp;
                //            eval_bit_set(tmp, sizeof(limb_type) * CHAR_BIT * (this->m_mod.backend().size() + 1));
                //            eval_decrement(tmp);
                //            eval_bitwise_and(t1, tmp);
                //         }
                //         //eval_mask_bits(t1, Backend::limb_bits * (this->m_mod.backend().size() + 1));
                //
                //         eval_subtract(t1, result, t1);
                //
                //         if (eval_lt(t1, 0))
                //         {
                //            Backend p2;
                //            eval_bit_set(p2, sizeof(limb_type) * CHAR_BIT * (this->m_mod.backend().size() + 1));
                //            eval_add(t1, p2);
                //         }
                //
                //         while (eval_lt(this->m_mod.backend(), t1) || (t1.compare(this->m_mod.backend()) == 0))
                //         {
                //            eval_subtract(t1, this->m_mod.backend());
                //         }
                //
                //         if (eval_lt(result, 0))
                //         {
                //            eval_add(t1, this->m_mod.backend());
                //         }
                //
                //         result = t1;
                //         return;
                //      }
                //      else
                //      {
                //         eval_modulus(result, this->m_mod.backend());
                //         return;
                //      }
                //   }
                //
                // protected:
                //   cpp_int m_mu; //number_type m_mu;
                //};

            }    // namespace backends
        }        // namespace multiprecision
    }            // namespace crypto3
}    // namespace nil

#endif    //_MULTIPRECISION_BARRETT_PARAMS_HPP
