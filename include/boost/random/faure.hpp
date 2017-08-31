/* boost random/faure.hpp header file
 *
 * Copyright Justinas Vygintas Daugmaudis 2010-2017
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * http://www.boost.org/LICENSE_1_0.txt)
 */

#ifndef BOOST_RANDOM_FAURE_HPP
#define BOOST_RANDOM_FAURE_HPP

#include <boost/random/detail/qrng_base.hpp>

#include <vector>
#include <algorithm>

#include <cmath>

#include <boost/assert.hpp>

#include <sstream>

//!\file
//!Describes the quasi-random number generator class template faure.

namespace boost {
namespace random {

/** @cond */
namespace detail {
namespace fr {

// There is no particular reason why 187 first primes were chosen
// to be put into this table. The only reason was, perhaps, that
// the number of dimensions for Faure generator would be around
// the same number as the number of dimensions supported by the
// Sobol qrng.
struct prime_table
{
  typedef unsigned short value_type;

  BOOST_STATIC_CONSTANT(int, number_of_primes = 187);

  // A function that returns lower bound prime for a given n
  static value_type lower_bound(std::size_t n)
  {
    static const value_type prim_a[number_of_primes] = {
      2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
      59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
      127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181,
      191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
      257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
      331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397,
      401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463,
      467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557,
      563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619,
      631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
      709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787,
      797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863,
      877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953,
      967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031,
      1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093,
      1097, 1103, 1109, 1117 };

    if (n > prim_a[number_of_primes - 1])
    {
      std::ostringstream os;
      os << "The Faure quasi-random number generator only supports up to "
        << prim_a[number_of_primes - 1] << " dimensions.";
      throw std::invalid_argument(os.str());
    }

    return *std::lower_bound(prim_a, prim_a + number_of_primes, n);
  }
};

// Returns the integer part of the logarithm base Base of arg.
// In erroneous situations, e.g., integer_log(base, 0) the function
// returns 0 and does not report the error. This is the intended
// behavior.
inline std::size_t integer_log(std::size_t base, std::size_t arg)
{
  std::size_t ilog = 0;
  while( base <= arg )
  {
    arg /= base; ++ilog;
  }
  return ilog;
}

// Perform exponentiation by squaring
inline std::size_t integer_pow(std::size_t base, std::size_t exp)
{
  std::size_t result = 1;
  while (exp)
  {
    if (exp & 1)
      result *= base;
    exp >>= 1;
    base *= base;
  }
  return result;
}

// Computes a table of binomial coefficients modulo qs.
template<typename RealType>
struct binomial_coefficients
{
  typedef RealType value_type;

  // Binomial values modulo qs_base will never be bigger than qs_base.
  // We can choose an appropriate integer type to hold modulo values and
  // shave off memory footprint.
  typedef prime_table::value_type packed_uint_t;

  // default copy c-tor is fine

  explicit binomial_coefficients(std::size_t dimension)
  {
    resize(dimension);
  }

  void resize(std::size_t dimension)
  {
    qs_base = fr::prime_table::lower_bound(dimension);
    inv_qs_base = static_cast<RealType>(1) / static_cast<RealType>(qs_base);

    // Throw away previously computed coefficients.
    // This will trigger recomputation on next update
    coeff.clear();
  }

  void update(std::size_t seq, std::vector<RealType>& quasi)
  {
    if (!quasi.empty())
    {
      const std::size_t hisum = n_elements(seq);
      if( coeff.size() != size_hint(hisum) )
        recompute_tables(hisum);
  
      typename std::vector<RealType>::iterator it = quasi.begin();
  
      *it = compute_recip(seq, hisum, ytemp.rbegin());
  
      // Find other components using the Faure method.
      ++it;
      for ( ; it != quasi.end(); ++it)
      {
        *it = RealType();
        RealType r = inv_qs_base;
  
        for (std::size_t i = 0; i != hisum; ++i)
        {
          RealType ztemp = RealType();
          for (std::size_t j = i; j != hisum; ++j)
            ztemp += ytemp[j] * upper_element(i, j, hisum);
  
          // Sum ( J <= I <= HISUM ) ( old ytemp(i) * binom(i,j) ) mod QS.
          ytemp[i] = std::fmod(ztemp, static_cast<RealType>(qs_base));
          *it += ytemp[i] * r;
          r *= inv_qs_base;
        }
      }
    }
  }

private:
  inline std::size_t n_elements(std::size_t seq) const
  {
    return integer_log(qs_base, seq) + 1;
  }

  inline static std::size_t size_hint(std::size_t n)
  {
    return n * (n + 1) / 2;
  }

  packed_uint_t& upper_element(std::size_t i, std::size_t j, std::size_t dim)
  {
    BOOST_ASSERT( i < dim );
    BOOST_ASSERT( j < dim );
    BOOST_ASSERT( i <= j );
    return coeff[(i * (2 * dim - i + 1)) / 2 + j - i];
  }

  template<typename Iterator>
  RealType compute_recip(std::size_t seq, std::size_t n, Iterator out) const
  {
    // Here we do
    //   Sum ( 0 <= J <= HISUM ) YTEMP(J) * QS**J
    //   Sum ( 0 <= J <= HISUM ) YTEMP(J) / QS**(J+1)
    // in one go
    RealType r = RealType();
    std::size_t m, k = integer_pow(qs_base, n - 1);
    for( ; n != 0; --n, ++out, seq = m, k /= qs_base )
    {
      m  = seq % k;
      RealType v  = (seq - m) / k; // RealType <- IntType
      r += v;
      r *= inv_qs_base;
      *out = v; // saves double dereference
    }
    return r;
  }

  void compute_coefficients(const std::size_t n)
  {
    // Resize and initialize to zero
    coeff.resize(size_hint(n));
    std::fill(coeff.begin(), coeff.end(), packed_uint_t());

    // The first row and the diagonal is assigned to 1
    upper_element(0, 0, n) = 1;
    for (std::size_t i = 1; i < n; ++i)
    {
      upper_element(0, i, n) = 1;
      upper_element(i, i, n) = 1;
    }

    // Computes binomial coefficients MOD qs_base
    for (std::size_t i = 1; i < n; ++i)
    {
      for (std::size_t j = i + 1; j < n; ++j)
      {
        upper_element(i, j, n) = ( upper_element(i, j-1, n) +
                                   upper_element(i-1, j-1, n) ) % qs_base;
      }
    }
  }

  void recompute_tables(std::size_t n)
  {
    ytemp.resize(n);
    compute_coefficients(n);
  }

private:
  packed_uint_t qs_base;
  RealType inv_qs_base;

  // here we cache precomputed data; note that binomial coefficients have
  // to be recomputed iff the integer part of the logarithm of seq changes,
  // which happens relatively rarely.
  std::vector<packed_uint_t> coeff; // packed upper (!) triangular matrix
  std::vector<RealType> ytemp;
};

}} // namespace detail::fr
/** @endcond */

//!class template faure implements a quasi-random number generator as described in
//! \blockquote
//!Henri Faure,
//!Discrepance de suites associees a un systeme de numeration (en dimension s),
//!Acta Arithmetica,
//!Volume 41, 1982, pages 337-351.
//! \endblockquote
//
//! \blockquote
//!Bennett Fox,
//!Algorithm 647:
//!Implementation and Relative Efficiency of Quasirandom
//!Sequence Generators,
//!ACM Transactions on Mathematical Software,
//!Volume 12, Number 4, December 1986, pages 362-376.
//! \endblockquote
//!
//!\attention\b Important: This implementation supports up to 229 dimensions.
//!
//!In the following documentation @c X denotes the concrete class of the template
//!faure returning objects of type @c RealType, u and v are the values of @c X.
//!
//!Some member functions may throw exceptions of type @c std::bad_alloc.
//!
//! \copydoc friendfunctions
template<typename RealType>
class faure : public detail::qrng_base<
                        faure<RealType>
                      , detail::fr::binomial_coefficients<RealType>
                      >
{
  typedef faure<RealType> self_t;

  typedef detail::fr::binomial_coefficients<RealType> lattice_t;
  typedef detail::qrng_base<self_t, lattice_t> base_t;

  friend class detail::qrng_base<self_t, lattice_t >;

public:
  typedef RealType result_type;

  /** @copydoc boost::random::niederreiter_base2::min() */
  static result_type min /** @cond */ BOOST_PREVENT_MACRO_SUBSTITUTION /** @endcond */ () { return static_cast<RealType>(0); }

  /** @copydoc boost::random::niederreiter_base2::max() */
  static result_type max /** @cond */ BOOST_PREVENT_MACRO_SUBSTITUTION /** @endcond */ () { return static_cast<RealType>(1); }

  //!Effects: Constructs the s-dimensional default Faure quasi-random number generator.
  //!
  //!Throws: bad_alloc, invalid_argument.
  explicit faure(std::size_t s)
    : base_t(s) // initialize the binomial table here
  {}

  /** @copydetails boost::random::niederreiter_base2::seed()
   * Throws: bad_alloc.
   */
  void seed()
  {
    seed(0);
  }

  /** @copydetails boost::random::niederreiter_base2::seed(std::size_t)
   * Throws: bad_alloc.
   */
  void seed(std::size_t init)
  {
    compute_seq(init);
    this->curr_elem = 0;
    this->seq_count = init;
  }

  //=========================Doxygen needs this!==============================

  //!Requirements: *this is mutable.
  //!
  //!Returns: Returns a successive element of an s-dimensional
  //!(s = X::dimension()) vector at each invocation. When all elements are
  //!exhausted, X::operator() begins anew with the starting element of a
  //!subsequent s-dimensional vector.
  //!
  //!Throws: bad_alloc.

  // Fixed in Doxygen 1.7.0 -- id 612458: Fixed problem handling @copydoc for function operators.
  result_type operator()()
  {
    return base_t::operator()();
  }

  /** @copydoc boost::random::niederreiter_base2::discard(std::size_t)
   * Throws: bad_alloc.
   */
  void discard(std::size_t z)
  {
    base_t::discard(z);
  }

private:
/** @cond hide_private_members */
  void compute_seq(std::size_t seq)
  {
    this->lattice.update(seq, this->quasi_state);
  }
  void compute_next()
  {
    compute_seq(++this->seq_count);
  }
/** @endcond */
};

} // namespace random

typedef random::faure<double> faure;

} // namespace boost

#endif // BOOST_RANDOM_FAURE_HPP
