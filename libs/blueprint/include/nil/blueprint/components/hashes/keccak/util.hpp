//---------------------------------------------------------------------------//
// Copyright (c) 2024 Elena Tatuzova   <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PACK_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_KECCAK_PACK_HPP

template <typename BlueprintFieldType>
typename BlueprintFieldType::value_type pack(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.data);
    integral_type result_integral = 0;
    integral_type power = 1;
    for (int i = 0; i < 64; ++i) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 1;
        power = power << 3;
    }
    return value_type(result_integral);
}

template<typename BlueprintFieldType>
typename BlueprintFieldType::value_type unpack(typename BlueprintFieldType::value_type value) {
    using value_type = typename BlueprintFieldType::value_type;
    using integral_type = typename BlueprintFieldType::integral_type;
    integral_type value_integral = integral_type(value.data);
    integral_type result_integral = 0;
    integral_type power = 1;
    while (value_integral >= 1) {
        integral_type bit = value_integral & 1;
        result_integral = result_integral + bit * power;
        value_integral = value_integral >> 3;
        power = power << 1;
    }
    return value_type(result_integral);
}

template <typename BlueprintFieldType>
typename BlueprintFieldType::value_type calculateRLC(
    std::vector<std::uint8_t> data,
    typename BlueprintFieldType::value_type factor
){
    typename BlueprintFieldType::value_type RLC = data.size();
    for( std::size_t i = 0; i < data.size(); i++ ){
        RLC *= factor;
        RLC += typename BlueprintFieldType::value_type(data[i]);
    }
    return RLC;
}

template <typename BlueprintFieldType>
std::array<typename BlueprintFieldType::value_type,4> sparsed_64bits_to_4_chunks(typename BlueprintFieldType::value_type num){
    using integral_type = typename BlueprintFieldType::integral_type;
    using value_type = typename BlueprintFieldType::value_type;
    integral_type n(num.data);
    integral_type mask = (integral_type(1) << 48) - 1;

    std::array<typename BlueprintFieldType::value_type,4> result;
    result[3] = value_type(n & mask); n >>= 48;
    result[2] = value_type(n & mask); n >>= 48;
    result[1] = value_type(n & mask); n >>= 48;
    result[0] = value_type(n & mask);

    return result;
}

// For 16-bit numbers placed into field element
template <typename BlueprintFieldType>
typename BlueprintFieldType::value_type swap_bytes( typename BlueprintFieldType::value_type i ){
    typename BlueprintFieldType::integral_type n(i.data);
    assert( n < 65536 );

    return ((n & 0xFF) << 8) + ((n & 0xFF00) >> 8);
}
#endif
