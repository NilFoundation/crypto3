//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Alexander Sokolov <asokolov@nil.foundation>
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

#define BOOST_TEST_MODULE hash_pack_test

#include <boost/array.hpp>
#include <boost/cstdint.hpp>

#include <boost/test/unit_test.hpp>
#include <boost/test/data/test_case.hpp>
#include <boost/test/data/monomorphic.hpp>

#include <nil/marshalling/algorithms/pack.hpp>
#include <nil/marshalling/types/integral.hpp>
#include <nil/marshalling/types/bitmask_value.hpp>
#include <nil/marshalling/types/enumeration.hpp>
#include <nil/marshalling/types/array_list.hpp>
#include <nil/marshalling/types/string.hpp>
#include <nil/marshalling/types/bitfield.hpp>
#include <nil/marshalling/types/optional.hpp>
#include <nil/marshalling/types/bundle.hpp>
#include <nil/marshalling/types/float_value.hpp>
#include <nil/marshalling/types/no_value.hpp>
#include <nil/marshalling/types/variant.hpp>

#include <cstdio>

using namespace nil::marshalling;

BOOST_AUTO_TEST_SUITE(pack_imploder_test_suite)

BOOST_AUTO_TEST_CASE(be_to_be_1) {
    
    using input_type = std::vector<std::uint8_t>;    
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<2>>;

    input_type in = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::vector<std::uint16_t> res = {{0x1234, 0x5678}};

    out = pack<output_type, typename input_type::iterator>(in.begin(), in.end());
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
        // std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(be_to_be_2) {

    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;

    input_type in;
    std::vector<std::uint16_t> inp_seed_blank = {0x1234, 0x5678, 0x90ab, 0xcdef};
    output_type out;
    std::array<uint32_t, 2> res = {{0x12345678, 0x90abcdef}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(be_to_le_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::integral<
                field_type<option::little_endian>, 
                std::uint32_t>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::uint32_t res = 0x78563412;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);

    // std::cout << std::hex << out.value() << std::endl;
    BOOST_CHECK(out.value() == res);
}


// BOOST_AUTO_TEST_CASE(bubb_to_bulb_1) {
//     using input_type = types::array_list<
//             field_type<option::little_endian>, 
//             types::integral<
//                 field_type<option::big_endian>, 
//                 std::uint8_t>,
//             option::fixed_size_storage<4>>;
//     using input_seed_type = typename input_type::value_type;
//     using output_type =  
//             types::integral<
//                 field_type<option::big_octet_little_bit>, 
//                 std::uint32_t>;

//     input_type in;
//     std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
//     output_type out;
//     std::uint32_t res = 0x482c6a1e;

//     input_seed_type &inp_seed = in.value();
    
//     for (auto it = inp_seed_blank.begin(); 
//               it != inp_seed_blank.end(); 
//               ++it){
//         inp_seed.push_back(typename input_seed_type::value_type(*it));
//     }

//     out = pack<input_type, output_type>(in);

//     std::cout << std::hex << out.value() << std::endl;
//     BOOST_CHECK(out.value() == res);
// }


// BOOST_AUTO_TEST_CASE(bubb_to_bulb_2) {
//     std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    // output_type out;
//     std::array<uint32_t, 2> res = {{0x482c6a1e, 0x09d5b3f7}};

//     pack<big_octet_big_bit, big_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(be_to_le_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<8>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::integral<
                field_type<option::little_endian>, 
                std::uint64_t>;

    input_type in;
    std::array<uint8_t, 8> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};
    output_type out;
    std::uint64_t res = 0xefcdab9078563412;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);

    BOOST_CHECK(out.value() == res);
}

BOOST_AUTO_TEST_CASE(be_to_le_3) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::array_list<
                field_type<option::little_endian>, 
                types::integral<
                    field_type<option::little_endian>, 
                    std::uint32_t>,
                option::fixed_size_storage<2>>;

    input_type in;
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x78563412, 0xefcdab90}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_lulb_4) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::integral<
                field_type<option::little_endian>, 
                std::uint32_t>;

    input_type in;
    std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    output_type out;
    uint32_t res = 0x78563412;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    BOOST_CHECK(out.value() == res);
}

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_1) {
//     using input_type = types::array_list<
//             field_type<option::little_endian>, 
//             types::integral<
//                 field_type<option::big_endian>, 
//                 std::uint16_t>,
//             option::fixed_size_storage<2>>;
//     using input_seed_type = typename input_type::value_type;
//     using output_type =  
//             types::integral<
//                 field_type<option::little_octet_little_bit>, 
//                 std::uint32_t>;

//     input_type in;
//     std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
//     output_type out;
//     uint32_t res = 0x1e6a2c48;

//     input_seed_type &inp_seed = in.value();
    
//     for (auto it = inp_seed_blank.begin(); 
//               it != inp_seed_blank.end(); 
//               ++it){
//         inp_seed.push_back(typename input_seed_type::value_type(*it));
//     }

//     out = pack<input_type, output_type>(in);

//     BOOST_CHECK(out.value() == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_2) {
//     std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    // output_type out;
//     std::array<uint16_t, 2> res = {{0x2c48, 0x1e6a}};

//     pack<big_octet_big_bit, little_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(lubb_to_bubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::integral<
                field_type<option::big_endian>, 
                std::uint64_t>;

    input_type in;
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    uint64_t res = 0x34127856ab90efcd;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    BOOST_CHECK(out.value() == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::array_list<
                field_type<option::little_endian>, 
                types::integral<
                    field_type<option::big_endian>, 
                    std::uint16_t>,
                option::fixed_size_storage<2>>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_1) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x12345678, 0x90abcdef}};
    // output_type out;
//     std::uint64_t res = {{0x1e6a2c48f7b3d509}};

//     pack<little_octet_big_bit, big_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_2) {
//     std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    // output_type out;
//     std::array<uint16_t, 2> res = {{0x482c, 0x6a1e}};

//     pack<little_octet_big_bit, big_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(lubb_to_lubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>;

    input_type in;
    std::array<uint8_t, 2> inp_seed_blank = {{0x56, 0x78}};
    output_type out;
    uint16_t res = 0x7856;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    BOOST_CHECK(out.value() == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type =  
            types::array_list<
                field_type<option::little_endian>, 
                types::integral<
                    field_type<option::little_endian>, 
                    std::uint32_t>,
                option::fixed_size_storage<2>>;

    input_type in;
    std::array<std::uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<std::uint32_t, 2> res = {{0x56781234, 0xcdef90ab}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

/*
BOOST_AUTO_TEST_CASE(lubb_to_lulb_1) {
    std::array<uint8_t, 8> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x1e6a2c48, 0xf7b3d509}};

    pack<little_octet_big_bit, little_octet_little_bit, 8, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lubb_to_lulb_2) {
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x6a1e482c, 0xb3f709d5}};

    pack<little_octet_big_bit, little_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bubb_1) {
    std::array<uint8_t, 16> inp_seed_blank = {
        {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x48, 0x2c, 0x6a, 0x1e, 0x09, 0xd5, 0xb3, 0xf7}};
    output_type out;
    std::array<uint64_t, 2> res = {{0x482c6a1e09d5b3f7, 0x1234567890abcdef}};

    pack<big_octet_little_bit, big_octet_big_bit, 8, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bubb_2) {
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x482c6a1e, 0x09d5b3f7}};

    pack<big_octet_little_bit, big_octet_big_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bulb_1) {
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x12345678, 0x90abcdef}};

    pack<big_octet_little_bit, big_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_bulb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    pack<big_octet_little_bit, big_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lubb_1) {
    std::array<uint16_t, 8> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef, 0x482c, 0x6a1e, 0x09d5, 0xb3f7}};
    output_type out;
    std::array<uint64_t, 2> res = {{0xf7b3d5091e6a2c48, 0xefcdab9078563412}};

    pack<big_octet_little_bit, little_octet_big_bit, 16, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lubb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x2c48, 0x1e6a}};

    pack<big_octet_little_bit, little_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lulb_1) {
    std::array<uint32_t, 4> inp_seed_blank = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};
    output_type out;
    std::array<uint64_t, 2> res = {{0xefcdab9078563412, 0xf7b3d5091e6a2c48}};

    pack<big_octet_little_bit, little_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(bulb_to_lulb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x3412, 0x7856}};

    pack<big_octet_little_bit, little_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bubb_1) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x48, 0x2c, 0x6a, 0x1e}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    pack<little_octet_little_bit, big_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bubb_2) {
    std::array<uint16_t, 4> inp_seed_blank = {{0x1234, 0x5678, 0x90ab, 0xcdef}};
    output_type out;
    std::array<uint32_t, 2> res = {{0x2c481e6a, 0xd509f7b3}};

    pack<little_octet_little_bit, big_octet_big_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bulb_1) {
    std::array<uint16_t, 2> inp_seed_blank = {{0x09d5, 0xb3f7}};
    output_type out;
    std::uint32_t res = {{0xd509f7b3}};

    pack<little_octet_little_bit, big_octet_little_bit, 16, 32>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_bulb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x1234, 0x5678}};

    pack<little_octet_little_bit, big_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lubb_1) {
    std::array<uint16_t, 4> inp_seed_blank = {{0x482c, 0x6a1e, 0x09d5, 0xb3f7}};
    output_type out;
    std::uint64_t res = {{0xcdef90ab56781234}};

    pack<little_octet_little_bit, little_octet_big_bit, 16, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lubb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x2c48, 0x1e6a}};

    pack<little_octet_little_bit, little_octet_big_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lulb_1) {
    std::array<uint32_t, 4> inp_seed_blank = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};
    output_type out;
    std::array<uint64_t, 2> res = {{0x90abcdef12345678, 0x09d5b3f7482c6a1e}};

    pack<little_octet_little_bit, little_octet_little_bit, 32, 64>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}

BOOST_AUTO_TEST_CASE(lulb_to_lulb_2) {
    std::array<uint8_t, 4> inp_seed_blank = {{0x12, 0x34, 0x56, 0x78}};
    output_type out;
    std::array<uint16_t, 2> res = {{0x3412, 0x7856}};

    pack<little_octet_little_bit, little_octet_little_bit, 8, 16>(in.begin(), in.end(), out.begin());

    BOOST_CHECK(out == res);
}*/

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(pack_exploder_test_suite)

BOOST_AUTO_TEST_CASE(bubb_to_bubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    output_type out;
    std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_bubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x12345678, 0x90abcdef}};
    output_type out;
    std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(bubb_to_bulb_1) {
//     using input_type = 
//             types::integral<
//                 field_type<option::big_endian>, 
//                 std::uint32_t>;
//     using input_seed_type = typename input_type::value_type;
//     using output_type = 
//         types::array_list<
//             field_type<option::little_endian>, 
//             types::integral<
//                 field_type<option::big_octet_little_bit>, 
//                 std::uint8_t>,
//             option::fixed_size_storage<4>>;

//     input_type in;   
//     std::uint32_t in = 0x482c6a1e;
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

//     pack<big_octet_big_bit, big_octet_little_bit, 32, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_bulb_2) {
//     using input_type = types::array_list<
//             field_type<option::little_endian>, 
//             types::integral<
//                 field_type<option::big_endian>, 
//                 std::uint32_t>,
//             option::fixed_size_storage<2>>;
//     using input_seed_type = typename input_type::value_type;
//     using output_type = 
//         types::array_list<
//             field_type<option::little_endian>, 
//             types::integral<
//                 field_type<option::big_octet_little_bit>, 
//                 std::uint16_t>,
//             option::fixed_size_storage<4>>;

//     input_type in;
//     std::array<uint32_t, 2> inp_seed_blank = {{0x482c6a1e, 0x09d5b3f7}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

//     pack<big_octet_big_bit, big_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(bubb_to_lubb_1) {
    using input_type = 
            types::integral<
                field_type<option::big_endian>, 
                std::uint64_t>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<8>>;

    std::uint64_t inp_seed_blank = 0xefcdab9078563412;
    output_type out;
    std::array<uint8_t, 8> res = {{0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12}};
    
    input_type in = input_type(input_seed_type(inp_seed_blank));

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_lubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x78563412, 0xefcdab90}};
    output_type out;
    std::array<uint16_t, 4> res = {{0x5678, 0x1234, 0xcdef, 0x90ab}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_1) {
//     std::uint32_t inp_seed_blank = {{0x1e6a2c48}};
    // output_type out;
//     std::array<uint16_t, 2> res = {{0x5678, 0x1234}};

//     pack<big_octet_big_bit, little_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x2c48, 0x1e6a}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

//     pack<big_octet_big_bit, little_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(lubb_to_bubb_1) {
    using input_type = 
            types::integral<
                field_type<option::little_endian>, 
                std::uint64_t>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;

    std::uint64_t inp_seed_blank = 0x34127856ab90efcd;
    output_type out;
    std::array<uint16_t, 4> res = {{0xcdef, 0x90ab, 0x5678, 0x1234}};

    input_type in = input_type(input_seed_type(inp_seed_blank));

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    output_type out;
    std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_1) {
//     std::uint64_t inp_seed_blank = {{0x1e6a2c48f7b3d509}};
    // output_type out;
//     std::array<uint32_t, 2> res = {{0x90abcdef, 0x12345678}};

//     pack<little_octet_big_bit, big_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x482c, 0x6a1e}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

//     pack<little_octet_big_bit, big_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(lubb_to_lubb_1) {
    using input_type = 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;

    std::uint16_t inp_seed_blank = 0x7856;
    output_type out;
    std::array<uint8_t, 2> res = {{0x56, 0x78}};
    input_type in = input_type(input_seed_type(inp_seed_blank));

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = 
        types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x56781234, 0xcdef90ab}};
    output_type out;
    std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(lubb_to_lulb_1) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x1e6a2c48, 0xf7b3d509}};
    // output_type out;
//     std::array<uint8_t, 8> res = {{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}};

//     pack<little_octet_big_bit, little_octet_little_bit, 32, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_lulb_2) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x6a1e482c, 0xb3f709d5}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

//     pack<little_octet_big_bit, little_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bubb_1) {
//     std::array<uint64_t, 2> inp_seed_blank = {{0x482c6a1e09d5b3f7, 0x1234567890abcdef}};
    // output_type out;
//     std::array<uint8_t, 16> res = {
//         {0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x48, 0x2c, 0x6a, 0x1e, 0x09, 0xd5, 0xb3, 0xf7}};

//     pack<big_octet_little_bit, big_octet_big_bit, 64, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bubb_2) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x482c6a1e, 0x09d5b3f7}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

//     pack<big_octet_little_bit, big_octet_big_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bulb_1) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x12345678, 0x90abcdef}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x1234, 0x5678, 0x90ab, 0xcdef}};

//     pack<big_octet_little_bit, big_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

//     pack<big_octet_little_bit, big_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lubb_1) {
//     std::array<uint64_t, 2> inp_seed_blank = {{0xf7b3d5091e6a2c48, 0xefcdab9078563412}};
    // output_type out;
//     std::array<uint16_t, 8> res = {{0xcdef, 0x90ab, 0x5678, 0x1234, 0xb3f7, 0x09d5, 0x6a1e, 0x482c}};

//     pack<big_octet_little_bit, little_octet_big_bit, 64, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lubb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x2c48, 0x1e6a}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

//     pack<big_octet_little_bit, little_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lulb_1) {
//     std::array<uint64_t, 2> inp_seed_blank = {{0xefcdab9078563412, 0xf7b3d5091e6a2c48}};
    // output_type out;
//     std::array<uint32_t, 4> res = {{0x90abcdef, 0x12345678, 0x09d5b3f7, 0x482c6a1e}};

//     pack<big_octet_little_bit, little_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x3412, 0x7856}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

//     pack<big_octet_little_bit, little_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bubb_1) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x2c, 0x48, 0x1e, 0x6a}};

//     pack<little_octet_little_bit, big_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bubb_2) {
//     std::array<uint32_t, 2> inp_seed_blank = {{0x2c481e6a, 0xd509f7b3}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x5678, 0x1234, 0xcdef, 0x90ab}};

//     pack<little_octet_little_bit, big_octet_big_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bulb_1) {
//     std::uint32_t inp_seed_blank = {{0xd509f7b3}};
    // output_type out;
//     std::array<uint16_t, 2> res = {{0xb3f7, 0x09d5}};

//     pack<little_octet_little_bit, big_octet_little_bit, 32, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x1234, 0x5678}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x34, 0x12, 0x78, 0x56}};

//     pack<little_octet_little_bit, big_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lubb_1) {
//     std::uint64_t inp_seed_blank = {{0xcdef90ab56781234}};
    // output_type out;
//     std::array<uint16_t, 4> res = {{0x482c, 0x6a1e, 0x09d5, 0xb3f7}};

//     pack<little_octet_little_bit, little_octet_big_bit, 64, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lubb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x2c48, 0x1e6a}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

//     pack<little_octet_little_bit, little_octet_big_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lulb_1) {
//     std::array<uint64_t, 2> inp_seed_blank = {{0x90abcdef12345678, 0x09d5b3f7482c6a1e}};
    // output_type out;
//     std::array<uint32_t, 4> res = {{0x12345678, 0x90abcdef, 0x482c6a1e, 0x09d5b3f7}};

//     pack<little_octet_little_bit, little_octet_little_bit, 64, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lulb_2) {
//     std::array<uint16_t, 2> inp_seed_blank = {{0x3412, 0x7856}};
    // output_type out;
//     std::array<uint8_t, 4> res = {{0x12, 0x34, 0x56, 0x78}};

//     pack<little_octet_little_bit, little_octet_little_bit, 16, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(pack_equal_test_suite)

BOOST_AUTO_TEST_CASE(bubb_to_bubb_1) {

    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x01928374, 0x65473829}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_bubb_2) {

    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint8_t, 2> inp_seed_blank = {{0x01, 0x23}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_bubb_3) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint8_t, 2> inp_seed_blank = {{0xC, 0x4}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x01928374, 0x65473829}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint8_t, 2> inp_seed_blank = {{0x01, 0x23}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_lubb_3) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = input_type;

    input_type in;
    std::array<uint8_t, 2> inp_seed_blank = {{0xC, 0x4}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(bulb_to_bulb_1) {

//     std::array<uint32_t, 2> inp_seed_blank = {{0x01928374, 0x65473829}};
//     output_type out;

//     pack<big_octet_little_bit, big_octet_little_bit, 32, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bulb_2) {

//     std::array<uint8_t, 2> inp_seed_blank = {{0x01, 0x23}};
//     output_type out;

//     pack<big_octet_little_bit, big_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bulb_3) {

//     std::array<uint8_t, 2> inp_seed_blank = {{0xC, 0x4}};
//     output_type out;

//     pack<big_octet_little_bit, big_octet_little_bit, 4, 4>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lulb_1) {

//     std::array<uint32_t, 2> inp_seed_blank = {{0x01928374, 0x65473829}};
//     output_type out;

//     pack<little_octet_little_bit, little_octet_little_bit, 32, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lulb_2) {

//     std::array<uint8_t, 2> inp_seed_blank = {{0x01, 0x23}};
//     output_type out;

//     pack<little_octet_little_bit, little_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lulb_3) {

//     std::array<uint8_t, 2> inp_seed_blank = {{0xC, 0x4}};
//     output_type out;

//     pack<little_octet_little_bit, little_octet_little_bit, 4, 4>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

BOOST_AUTO_TEST_CASE(bubb_to_lubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_lubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x8, 0xa, 0x5, 0xe}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(bubb_to_lubb_3) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint16_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint16_t, 4> inp_seed_blank = {{0x89ad, 0x56ef, 0x7340, 0x12cb}};
    output_type out;
    std::array<uint16_t, 4> res = {{0xad89, 0xef56, 0x4073, 0xcb12}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(bubb_to_bulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<big_octet_big_bit, big_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_bulb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x89ad, 0x56ef, 0x7340, 0x12cb}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0x91b5, 0x6af7, 0xce02, 0x48d3}};

//     pack<big_octet_big_bit, big_octet_little_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<big_octet_big_bit, little_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bubb_to_lulb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x89ad, 0x56ef, 0x7340, 0x12cb}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0xb591, 0xf76a, 0x02ce, 0xd348}};

//     pack<big_octet_big_bit, little_octet_little_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_CASE(lubb_to_bubb_1) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb_2) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint8_t>,
            option::fixed_size_storage<4>>;

    input_type in;
    std::array<uint8_t, 4> inp_seed_blank = {{0x8, 0xa, 0x5, 0xe}};
    output_type out;

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == inp_seed_blank.size());

    auto it = out_value.begin();
    auto res_it = inp_seed_blank.begin();
    for (; it != out_value.end(), res_it != inp_seed_blank.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

BOOST_AUTO_TEST_CASE(lubb_to_bubb_3) {
    using input_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::little_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;
    using input_seed_type = typename input_type::value_type;
    using output_type = types::array_list<
            field_type<option::little_endian>, 
            types::integral<
                field_type<option::big_endian>, 
                std::uint32_t>,
            option::fixed_size_storage<2>>;

    input_type in;
    std::array<uint32_t, 2> inp_seed_blank = {{0x89ad56ef, 0x734012cb}};
    output_type out;
    std::array<uint32_t, 2> res = {{0xef56ad89, 0xcb124073}};

    input_seed_type &inp_seed = in.value();
    
    for (auto it = inp_seed_blank.begin(); 
              it != inp_seed_blank.end(); 
              ++it){
        inp_seed.push_back(typename input_seed_type::value_type(*it));
    }

    out = pack<input_type, output_type>(in);
    auto out_value = out.value();

    BOOST_CHECK(out_value.size() == res.size());

    auto it = out_value.begin();
    auto res_it = res.begin();
    for (; it != out_value.end(), res_it != res.end(); 
            ++it, ++res_it){
    //     std::cout << std::hex << int((*it).value()) << std::dec << std::endl;
        BOOST_CHECK(int((*it).value()) == (*res_it));
    }
}

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<little_octet_big_bit, big_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_bulb_2) {

//     std::array<uint32_t, 2> inp_seed_blank = {{0x89ad56ef, 0x734012cb}};
//     output_type out;
//     std::array<uint32_t, 2> res = {{0xf76ab591, 0xd34802ce}};

//     pack<little_octet_big_bit, big_octet_little_bit, 32, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_lulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<little_octet_big_bit, little_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lubb_to_lulb_2) {

//     std::array<uint32_t, 2> inp_seed_blank = {{0x89ad56ef, 0x734012cb}};
//     output_type out;
//     std::array<uint32_t, 2> res = {{0x91b56af7, 0xce0248d3}};

//     pack<little_octet_big_bit, little_octet_little_bit, 32, 32>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bubb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<little_octet_little_bit, big_octet_big_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bubb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0x98f0, 0x146a, 0xce53, 0xb27d}};

//     pack<little_octet_little_bit, big_octet_big_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;

//     pack<little_octet_little_bit, big_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_bulb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0x190f, 0x2856, 0x73ca, 0x4dbe}};

//     pack<little_octet_little_bit, big_octet_little_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lubb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<little_octet_little_bit, little_octet_big_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(lulb_to_lubb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0xf098, 0x6a14, 0x53ce, 0x7db2}};

//     pack<little_octet_little_bit, little_octet_big_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bubb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<big_octet_little_bit, big_octet_big_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_bubb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0xf098, 0x6a14, 0x53ce, 0x7db2}};

//     pack<big_octet_little_bit, big_octet_big_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lubb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;
//     std::array<uint8_t, 4> res = {{0x91, 0xb5, 0x6a, 0xf7}};

//     pack<big_octet_little_bit, little_octet_big_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lubb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0x98f0, 0x146a, 0xce53, 0xb27d}};

//     pack<big_octet_little_bit, little_octet_big_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lulb_1) {

//     std::array<uint8_t, 4> inp_seed_blank = {{0x89, 0xad, 0x56, 0xef}};
//     output_type out;

//     pack<big_octet_little_bit, little_octet_little_bit, 8, 8>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == in);
// }

// BOOST_AUTO_TEST_CASE(bulb_to_lulb_2) {

//     std::array<uint16_t, 4> inp_seed_blank = {{0x0f19, 0x5628, 0xca73, 0xbe4d}};
//     output_type out;
//     std::array<uint16_t, 4> res = {{0x190f, 0x2856, 0x73ca, 0x4dbe}};

//     pack<big_octet_little_bit, little_octet_little_bit, 16, 16>(in.begin(), in.end(), out.begin());

//     BOOST_CHECK(out == res);
// }

BOOST_AUTO_TEST_SUITE_END()
