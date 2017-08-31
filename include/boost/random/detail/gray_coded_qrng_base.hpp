/* boost random/detail/gray_coded_qrng_base.hpp header file
 *
 * Copyright Justinas Vygintas Daugmaudis 2010-2017
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_BASE_HPP
#define BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_BASE_HPP

#include <boost/random/detail/qrng_base.hpp>

// Prerequisite headers for bitscan to work
#include <limits.h>
#include <boost/mpl/if.hpp>
#include <boost/type_traits/make_unsigned.hpp>
#include <boost/multiprecision/detail/bitscan.hpp> // find_lsb

//!\file
//!Describes the gray-coded quasi-random number generator base class template.

namespace boost {
namespace random {

namespace detail {

template<typename DerivedT, typename LatticeT>
class gray_coded_qrng_base : public qrng_base<DerivedT, LatticeT>
{
private:
  typedef gray_coded_qrng_base<DerivedT, LatticeT> self_t;
  typedef qrng_base<DerivedT, LatticeT> base_t;

  // The base needs to access modifying member f-ns, and we
  // don't want these functions to be available for the public use
  friend class qrng_base<DerivedT, LatticeT>;

public:
  typedef typename LatticeT::value_type result_type;

  explicit gray_coded_qrng_base(std::size_t dimension)
    : base_t(dimension)
  {}

  // default copy c-tor is fine

  // default assignment operator is fine

protected:
  void seed(std::size_t init, const char *msg)
  {
    this->curr_elem = 0;
    if (init != this->seq_count)
    {
      base_t::derived().seed();

      this->seq_count = init;
      init ^= (init / 2);
      for (int r = 0; init != 0; ++r, init >>= 1)
      {
        if (init & 1)
          update_quasi(r, msg);
      }
    }
  }

private:
  // Compute next state for this QRNG
  void compute_next()
  {
    compute_seq(this->seq_count++);
  }

  void compute_seq(std::size_t cnt)
  {
    // Find the position of the least-significant zero in sequence count.
    // This is the bit that changes in the Gray-code representation as
    // the count is advanced.
    int r = multiprecision::detail::find_lsb(~cnt);
    update_quasi(r, "compute_seq");
  }

  void update_quasi(int r, const char* msg)
  {
    if (r < LatticeT::bit_count)
    {
      // Calculate the next state.
      for (std::size_t i = 0; i != this->dimension(); ++i)
        this->quasi_state[i] ^= this->lattice(r, i);
    }
    else
    {
      boost::throw_exception( std::overflow_error(msg) );
    }
  }
};

}} // namespace detail::random

} // namespace boost

#endif // BOOST_RANDOM_DETAIL_GRAY_CODED_QRNG_BASE_HPP
