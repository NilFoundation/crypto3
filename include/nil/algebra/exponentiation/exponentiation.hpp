
#ifndef EXPONENTIATION_HPP_
#define EXPONENTIATION_HPP_

#include <cstdint>
#include <boost/multiprecision/number.hpp>
#include <boost/multiprecision/detail/integer_ops.hpp>

namespace nil {
    namespace algebra {

template<typename FieldT, typename Backend, expression_template_option ExpressionTemplates>
FieldT power(const FieldT &base, const number<Backend, ExpressionTemplates> &exponent)
{	
    FieldT result = FieldT::one();
 
    bool found_one = false;

    for (long i = msb(exponent); i >= 0; --i)
    {
        if (found_one)
        {
            result = result * result;
        }

        if (bit_test(exponent, i))
        {
            found_one = true;
            result = result * base;
        }
    }

    return result;
}

}
}

#endif // EXPONENTIATION_HPP_