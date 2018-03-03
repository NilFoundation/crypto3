/* boost random/detail/gray_coded_qrng.hpp header file
 *
 * Copyright Justinas Vygintas Daugmaudis 2010-2018
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_HPP
#define BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_HPP

#include <boost/random/detail/qrng_base.hpp>

#include <boost/multiprecision/integer.hpp> // lsb

#include <functional> // bit_xor

#include <boost/mpl/if.hpp>

//!\file
//!Describes the gray-coded quasi-random number generator base class template.

namespace boost {
namespace random {

namespace detail {

template<typename LatticeT>
class gray_coded_qrng
  : public qrng_base<
      gray_coded_qrng<LatticeT>
    , LatticeT
    , typename LatticeT::value_type
    >
{
public:
  typedef typename LatticeT::value_type result_type;
  typedef result_type size_type;

private:
  typedef gray_coded_qrng<LatticeT> self_t;
  typedef qrng_base<self_t, LatticeT, size_type> base_t;

  // The base needs to access modifying member f-ns, and we
  // don't want these functions to be available for the public use
  friend class qrng_base<self_t, LatticeT, size_type>;

  // Respect lattice bit_count here
  struct do_nothing {
    inline static void check(unsigned) {}
    inline static void check_log2(size_type) {}
  };
  struct check_bit_range {
    inline static void check(unsigned bit_pos) {
      if (bit_pos >= LatticeT::bit_count)
        boost::throw_exception( std::range_error("gray_coded_qrng: bit_count") );
    }
    inline static void check_log2(size_type code) {
      check_bit_range::check(multiprecision::msb(code));
    }
  };

  // We only want to check whether bit pos is outside the range if given bit_count
  // is narrower than the size_type, otherwise checks compile to nothing.
  typedef typename mpl::if_c<
      LatticeT::bit_count < std::numeric_limits<size_type>::digits
    , check_bit_range
    , do_nothing
  >::type bit_range_checker_t;

public:
  //!Returns: Tight lower bound on the set of values returned by operator().
  //!
  //!Throws: nothing.
  static BOOST_CONSTEXPR result_type min BOOST_PREVENT_MACRO_SUBSTITUTION ()
  { return 0; }

  //!Returns: Tight upper bound on the set of values returned by operator().
  //!
  //!Throws: nothing.
  static BOOST_CONSTEXPR result_type max BOOST_PREVENT_MACRO_SUBSTITUTION ()
  { return (std::numeric_limits<result_type>::max)(); }

  explicit gray_coded_qrng(std::size_t dimension)
    : base_t(dimension)
  {}

  // default copy c-tor is fine

  // default assignment operator is fine

  void seed()
  {
    set_zero_state();
    update_quasi(0);
    base_t::reset_seq(0);
  }

  void seed(const size_type init)
  {
    if (init != this->curr_seq())
    {
      size_type seq_code = boost::next(init);
      if (BOOST_UNLIKELY(!(init < seq_code)))
        boost::throw_exception( std::range_error("gray_coded_qrng: seed") );

      seq_code ^= (seq_code >> 1);
      // Fail if we see that seq_code is outside bit range.
      // We do that before we even touch engine state.
      bit_range_checker_t::check_log2(seq_code);

      set_zero_state();
      for (unsigned r = 0; seq_code != 0; ++r, seq_code >>= 1)
      {
        if (seq_code & static_cast<size_type>(1))
          update_quasi(r);
      }
    }
    // Everything went well, set the new seq count
    base_t::reset_seq(init);
  }

private:
  void compute_seq(size_type seq)
  {
    // Find the position of the least-significant zero in sequence count.
    // This is the bit that changes in the Gray-code representation as
    // the count is advanced.
    unsigned r = multiprecision::lsb(~seq);
    bit_range_checker_t::check(r);
    update_quasi(r);
  }

  void update_quasi(unsigned r)
  {
    // Calculate the next state.
    std::transform(this->state_begin(), this->state_end(),
      this->lattice.iter_at(r * this->dimension()), this->state_begin(),
      std::bit_xor<result_type>());
  }

  void set_zero_state()
  {
    std::fill(this->state_begin(), this->state_end(), result_type /*zero*/ ());
  }
};

}} // namespace detail::random

} // namespace boost

#endif // BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_HPP
