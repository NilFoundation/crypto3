
#ifndef EXPONENTIATION_HPP_
#define EXPONENTIATION_HPP_

#include <cstdint>

namespace nil {
    namespace algebra {

template<typename FieldT, typename PowerType>
FieldT power(const FieldT &base, const PowerType &exponent)
{	
	using default_ops::eval_bit_test;
	using default_ops::eval_msb;

    FieldT result = FieldT::one();
 
    bool found_one = false;

    for (long i = eval_msb(exponent); i >= 0; --i)
    {
        if (found_one)
        {
            result = result * result;
        }

        if (eval_bit_test(exponent, i))
        {
            found_one = true;
            result = result * base;
        }
    }

    return result;
}

template<typename FieldT, typename PowerType>
FieldT power(const FieldT &base, const unsigned long exponent)
{
    return power<FieldT>(base, (PowerType)(exponent));
}

template<typename FieldT, typename PowerType>
FieldT power(const FieldT &base, const PowerType &exponent);

template<typename FieldT>
FieldT power(const FieldT &base, const unsigned long exponent);

}
}

#endif // EXPONENTIATION_HPP_