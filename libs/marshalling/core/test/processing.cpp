//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE marshalling_processing_test

#include <boost/test/unit_test.hpp>

#include <nil/marshalling/type_traits.hpp>
#include <nil/marshalling/status_type.hpp>

#include <nil/marshalling/types/array_list/type_traits.hpp>
#include <nil/marshalling/types/string/type_traits.hpp>

#include <nil/marshalling/container/array_view.hpp>
#include <nil/marshalling/container/static_vector.hpp>
#include <nil/marshalling/container/static_string.hpp>
#include <nil/marshalling/container/string_view.hpp>
#include <nil/marshalling/container/type_traits.hpp>

using namespace nil::marshalling;

BOOST_TEST_DONT_PRINT_LOG_VALUE(status_type)

BOOST_AUTO_TEST_SUITE(marshalling_processing_test_suite)

BOOST_AUTO_TEST_CASE(test1) {
    typedef container::static_vector<std::uint8_t, 20> static_vector;

    static const std::uint8_t Data[] = {0, 1, 2, 3, 4, 5, 6};
    static const auto DataSize = std::extent<decltype(Data)>::value;

    static_vector vec;
    BOOST_CHECK(vec.empty());
    vec.assign(std::begin(Data), std::end(Data));
    BOOST_CHECK(vec.size() == DataSize);
    BOOST_CHECK(std::equal(vec.begin(), vec.end(), std::begin(Data)));

    static const std::uint8_t InsData1[] = {7, 8, 9};
    static const auto InsData1Size = std::extent<decltype(InsData1)>::value;
    auto iter = vec.insert(vec.end(), std::begin(InsData1), std::end(InsData1));
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize));

    static const std::uint8_t InsElem = 0xff;
    iter = vec.insert(vec.begin() + DataSize, InsElem);
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size + 1);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize + 1));
    BOOST_CHECK(*iter == InsElem);

    iter = vec.erase(iter);
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize));

    static const std::uint8_t InsData2[] = {0xaa, 0xbb};
    static const auto InsData2Size = std::extent<decltype(InsData2)>::value;

    iter = vec.insert(vec.begin() + DataSize, std::begin(InsData2), std::end(InsData2));
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size + InsData2Size);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData2), std::end(InsData2), vec.begin() + DataSize));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize + InsData2Size));

    iter = vec.erase(vec.begin() + DataSize, vec.begin() + DataSize + InsData2Size);
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize));

    static const std::uint8_t InsData3[] = {0xaa, 0xbb, 0xcc, 0xdd};
    static const auto InsData3Size = std::extent<decltype(InsData3)>::value;

    iter = vec.insert(vec.begin() + DataSize, std::begin(InsData3), std::end(InsData3));
    BOOST_CHECK(iter == vec.begin() + DataSize);
    BOOST_CHECK(vec.size() == DataSize + InsData1Size + InsData3Size);
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec.begin()));
    BOOST_CHECK(std::equal(std::begin(InsData3), std::end(InsData3), vec.begin() + DataSize));
    BOOST_CHECK(std::equal(std::begin(InsData1), std::end(InsData1), vec.begin() + DataSize + InsData3Size));
}

BOOST_AUTO_TEST_CASE(test2) {
    typedef container::static_vector<std::uint8_t, 20> Vec1;
    typedef container::static_vector<std::uint8_t, 40> Vec2;

    static const std::uint8_t Data1[] = {0, 1, 2, 3, 4, 5, 6};

    static const auto Data1Size = std::extent<decltype(Data1)>::value;

    Vec1 v1(std::begin(Data1), std::end(Data1));
    BOOST_CHECK(v1.size() == Data1Size);

    Vec2 v2(v1);
    BOOST_CHECK(v2.size() == Data1Size);
    BOOST_CHECK(v1 == v2);

    static const std::uint8_t Data2[] = {0x1a, 0x1b, 0x1c};
    static const auto Data2Size = std::extent<decltype(Data2)>::value;

    v2.assign(std::begin(Data2), std::end(Data2));
    BOOST_CHECK(v2.size() == Data2Size);
    BOOST_CHECK(v1 < v2);

    std::swap(v1, v2);
    BOOST_CHECK(v1.size() == Data2Size);
    BOOST_CHECK(v2.size() == Data1Size);
    BOOST_CHECK(std::equal(v1.begin(), v1.end(), std::begin(Data2)));
    BOOST_CHECK(std::equal(v2.begin(), v2.end(), std::begin(Data1)));
}

BOOST_AUTO_TEST_CASE(test3) {
    typedef container::static_string<20> Str;
    typedef container::static_string<30> Str2;

    Str str1;
    BOOST_CHECK(str1.empty());

    Str str2(5U, 'a');
    BOOST_CHECK(str2.size() == 5U);
    BOOST_CHECK(str2 == "aaaaa");
    BOOST_CHECK(str2 < "aaaab");
    BOOST_CHECK("aaa" < str2);
    BOOST_CHECK(str2 < "aab");

    Str2 str3(str2, 2);
    BOOST_CHECK(str3.size() == 3U);
    BOOST_CHECK(str3 == "aaa");

    Str str4("hello", 100);
    BOOST_CHECK(str4.size() == 5U);
    BOOST_CHECK(str4 == "hello");

    Str str5("bla");
    BOOST_CHECK(str5.size() == 3U);
    BOOST_CHECK(str5 == "bla");

    static const std::vector<char> Data = {'a', 'b', 'c', 'd'};

    Str str6(Data.begin(), Data.end());
    BOOST_CHECK(str6.size() == 4U);
    BOOST_CHECK(str6 == "abcd");

    Str2 str7(str6);
    BOOST_CHECK(str6 == str7);

    Str str8 = {'d', 'e', 'a', 'd'};
    BOOST_CHECK(str8.size() == 4U);
    BOOST_CHECK(str8 == "dead");
}

BOOST_AUTO_TEST_CASE(test4) {
    typedef container::static_string<20> Str1;
    typedef container::static_string<30> Str2;

    Str1 str1("bla");
    Str2 str2("hello");

    BOOST_CHECK(str1 != str2);
    BOOST_CHECK(str1 < str2);

    str2 = str1;
    BOOST_CHECK(str1 == str2);

    str1 = "dead";
    BOOST_CHECK(str1.size() == 4U);
    BOOST_CHECK(str1 == "dead");

    str2 = 'a';
    BOOST_CHECK(str2.size() == 1U);
    BOOST_CHECK(str2 == "a");

    str1 = {'b', 'e', 'e'};
    BOOST_CHECK(str1.size() == 3U);
    BOOST_CHECK(str1 == "bee");
}

BOOST_AUTO_TEST_CASE(test5) {
    typedef container::static_string<20> Str1;
    typedef container::static_string<30> Str2;

    Str1 str1("bla");
    Str2 str2("hello");

    BOOST_CHECK(str1 != str2);
    BOOST_CHECK(str1 < str2);

    str1.assign(3, 'a');
    BOOST_CHECK(str1.size() == 3U);
    BOOST_CHECK(str1 == "aaa");

    str2.assign(str1);
    BOOST_CHECK(str1 == str2);

    str1.assign(str2, 2);
    BOOST_CHECK(str1.size() == 1U);
    BOOST_CHECK(str1 == "a");

    str2.assign("abcdefgh", 4);
    BOOST_CHECK(str2.size() == 4U);
    BOOST_CHECK(str2 == "abcd");

    static const std::vector<char> Data = {'a', 'b', 'c', 'd'};

    str1.assign(Data.begin(), Data.end());
    BOOST_CHECK(str1.size() == 4U);
    BOOST_CHECK(str1 == "abcd");

    str1.assign({'b', 'e', 'e'});
    BOOST_CHECK(str1.size() == 3U);
    BOOST_CHECK(str1.length() == 3U);
    BOOST_CHECK(str1 == "bee");
}

BOOST_AUTO_TEST_CASE(test6) {
    typedef container::static_string<20> Str;

    Str str("hello");

    str.at(0) = 'b';
    BOOST_CHECK(str == "bello");

    str[4] = 'a';
    BOOST_CHECK(str == "bella");

    BOOST_CHECK(str.front() == 'b');
    str.front() = 'h';
    BOOST_CHECK(str.front() == 'h');
    BOOST_CHECK(str == "hella");

    BOOST_CHECK(str.back() == 'a');
    str.back() = 'o';
    BOOST_CHECK(str.back() == 'o');
    BOOST_CHECK(str == "hello");
    //    BOOST_CHECK(str.data() == "hello");
    //    BOOST_CHECK(str.c_str() == "hello");
}

BOOST_AUTO_TEST_CASE(test7) {
    typedef container::static_string<20> Str1;
    typedef container::static_string<10> Str2;

    Str1 str1("hello");
    Str2 str2;

    BOOST_CHECK(!str1.empty());
    BOOST_CHECK(str2.empty());

    std::copy(str1.cbegin(), str1.cend(), std::back_inserter(str2));
    BOOST_CHECK(str1 == str2);

    str1.assign(str2.begin() + 2, str2.end());
    BOOST_CHECK(str1 == "llo");

    str1.assign(str2.rbegin() + 1, str2.rend());
    BOOST_CHECK(str1 == "lleh");

    BOOST_CHECK(!str1.empty());
    str1.clear();
    BOOST_CHECK(str1.empty());

    BOOST_CHECK(str1.max_size() == 20U);
    BOOST_CHECK(str2.capacity() == 10U);
}

BOOST_AUTO_TEST_CASE(test8) {
    typedef container::static_string<20> Str;

    static const char *OrigStr = "hello";
    Str str(OrigStr);

    str.insert(5, 2, 'a');
    BOOST_CHECK(str == "helloaa");
    str.erase(5, 2);
    BOOST_CHECK(str == OrigStr);

    str.insert(0, "bla");
    BOOST_CHECK(str == "blahello");
    str.erase(0, 3);
    BOOST_CHECK(str == OrigStr);

    str.insert(2, "bla", 1);
    BOOST_CHECK(str == "hebllo");
    str.erase(2, 1);
    BOOST_CHECK(str == OrigStr);

    Str str2("dead");
    str.insert(3, str2);
    BOOST_CHECK(str == "heldeadlo");
    str.erase(3, 4);
    BOOST_CHECK(str == OrigStr);

    str.insert(3, str2, 1, 2);
    BOOST_CHECK(str == "helealo");
    str.erase(3, 2);
    BOOST_CHECK(str == OrigStr);

    str.insert(str.begin(), 'a');
    BOOST_CHECK(str == "ahello");
    str.erase(str.cbegin(), str.cbegin() + 1);
    BOOST_CHECK(str == OrigStr);

    str.insert(str.end(), 2, 'a');
    BOOST_CHECK(str == "helloaa");
    str.erase(str.end() - 2, str.end());
    BOOST_CHECK(str == OrigStr);

    str.insert(str.end() - 1, 3, 'a');
    BOOST_CHECK(str == "hellaaao");
    str.erase(str.end() - 4, str.end() - 1);
    BOOST_CHECK(str == OrigStr);

    str.insert(str.cbegin() + 1, str2.cbegin(), str2.cend());
    BOOST_CHECK(str == "hdeadello");
    str.erase(str.cbegin() + 1, str.cbegin() + 5);
    BOOST_CHECK(str == OrigStr);

    str.insert(str.end(), {'a', 'b', 'c'});
    BOOST_CHECK(str == "helloabc");
    str.erase(str.end() - 1);
    str.erase(str.end() - 1);
    str.erase(str.end() - 1);
    BOOST_CHECK(str == OrigStr);

    str.push_back('z');
    BOOST_CHECK(str == "helloz");
    str.pop_back();
    BOOST_CHECK(str == OrigStr);
}

BOOST_AUTO_TEST_CASE(test9) {
    typedef container::static_string<100> Str;
    typedef container::static_string<20> Str2;

    Str str("abc");
    Str2 strTmp("ABCDEFGHIJK");
    Str2 strTmp2("zzz");

    str.append(2, 'd')
        .append(strTmp2)
        .append(strTmp, 8)
        .append("bla")
        .append("xxx", 1)
        .append(strTmp2.begin(), strTmp2.end())
        .append({'d', 'e', 'a', 'd'});

    BOOST_CHECK(str == "abcddzzzIJKblaxzzzdead");
}

BOOST_AUTO_TEST_CASE(test10) {
    typedef container::static_string<100> Str;
    typedef container::static_string<20> Str2;

    Str str("abc");
    Str2 strTmp("ABCDEFGHIJK");

    (((str += strTmp) += 'z') += "hello") += {'d', 'e', 'a', 'd'};

    BOOST_CHECK(str == "abcABCDEFGHIJKzhellodead");
}

BOOST_AUTO_TEST_CASE(test11) {
    typedef container::static_string<100> Str;
    typedef container::static_string<20> Str2;

    Str str("abcdefghijklmnopqrst");
    Str2 str2("fghijklm");

    BOOST_CHECK(str.compare(str2) < 0);
    BOOST_CHECK(str.compare(5, 8, str2) == 0);
    BOOST_CHECK(0 < str.compare(5, 8, str2, 0, 7));
    BOOST_CHECK(str2.compare("fghijklm") == 0);
    BOOST_CHECK(0 < str2.compare(1, 2, "fghijklm"));
    BOOST_CHECK(0 == str.compare(5, 2, "fghijklm", 2));
}

BOOST_AUTO_TEST_CASE(test12) {
    typedef container::static_string<100> Str;
    typedef container::static_string<50> Str2;

    Str str("abcdefg");
    Str2 str2("HIJKLMNOP");

    str.replace(2, 2, str2);
    BOOST_CHECK(str == "abHIJKLMNOPefg");

    str.replace(str.begin() + 1, str.begin() + 11, str2);
    BOOST_CHECK(str == "aHIJKLMNOPefg");

    str.replace(0, 5, str2, 2, 3);
    BOOST_CHECK(str == "JKLLMNOPefg");

    str.replace(str.begin(), str.end(), str2.begin(), str2.begin() + 6);
    BOOST_CHECK(str == "HIJKLM");

    str.replace(0, 3, "abcdefg", 4);
    BOOST_CHECK(str == "abcdKLM");

    str.replace(str.cbegin() + 4, str.cbegin() + 7, "AAABBB", 4);
    BOOST_CHECK(str == "abcdAAAB");

    str.replace(1, 7, "bla");
    BOOST_CHECK(str == "abla");

    str.replace(str.end() - 2, str.end(), "hello");
    BOOST_CHECK(str == "abhello");

    str.replace(0, 3, 2, 'z');
    BOOST_CHECK(str == "zzello");

    str.replace(str.begin() + 2, str.begin() + 4, 3, 'x');
    BOOST_CHECK(str == "zzxxxlo");

    str.replace(str.begin(), str.end(), {'h', 'h', 'h'});
    BOOST_CHECK(str == "hhh");
}

BOOST_AUTO_TEST_CASE(test13) {
    typedef container::static_string<100> Str;

    Str str("hello");
    auto str2 = str.substr(2);
    BOOST_CHECK(str2 == "llo");

    str2 = str.substr(1, 3);
    BOOST_CHECK(str2 == "ell");
}

BOOST_AUTO_TEST_CASE(test14) {
    typedef container::static_string<100> Str;

    Str str("hello");

    char buf[100] = {0};

    auto count = str.copy(&buf[0], 4, 1);
    BOOST_CHECK(count == 4);

    BOOST_CHECK(std::equal(std::begin(buf), std::begin(buf) + count, str.begin() + 1));
}

BOOST_AUTO_TEST_CASE(test15) {
    typedef container::static_string<100> Str;

    Str str("hello");

    str.resize(4U);
    BOOST_CHECK(str == "hell");
    BOOST_CHECK(str.size() == 4U);

    str.resize(6U, 'o');
    BOOST_CHECK(str == "helloo");
}

BOOST_AUTO_TEST_CASE(test16) {
    typedef container::static_string<100> Str1;
    typedef container::static_string<50> Str2;

    Str1 str1("hello");
    Str2 str2("dead beef");

    std::swap(str1, str2);
    BOOST_CHECK(str1 == "dead beef");
    BOOST_CHECK(str1.size() == 9U);
    BOOST_CHECK(str2 == "hello");
    BOOST_CHECK(str2.size() == 5U);
}

BOOST_AUTO_TEST_CASE(test17) {
    typedef container::static_string<100> Str;

    Str str1("abcdefabc");
    Str emptyStr;

    Str str2("def");
    BOOST_CHECK(str1.find(str2) == 3U);

    Str str3("abc");
    BOOST_CHECK(str1.find(str3, 1) == 6U);
    BOOST_CHECK(str1.find("abcdef", 2, 3) == 6U);
    BOOST_CHECK(str1.find("abcdef", 2) == Str::npos);
    BOOST_CHECK(str1.find('b', 2) == 7U);
    BOOST_CHECK(emptyStr.find(str3) == Str::npos);

    BOOST_CHECK(str1.rfind(str3) == 6U);
    BOOST_CHECK(str1.rfind(str3, 5U) == 0U);
    BOOST_CHECK(str1.rfind("defbbb", Str::npos, 3U) == 3U);
    BOOST_CHECK(str1.rfind("abc", 6U, 3U) == 6U);
    BOOST_CHECK(str1.rfind("bcd") == 1U);
    BOOST_CHECK(str1.rfind('b') == 7U);
    BOOST_CHECK(str1.rfind('b', 5) == 1U);
    BOOST_CHECK(str1.rfind('c', 8U) == 8U);
    BOOST_CHECK(emptyStr.rfind(str3) == Str::npos);

    Str str4("cd");
    BOOST_CHECK(str1.find_first_of(str4) == 2U);
    BOOST_CHECK(str1.find_first_of(str4, 2U) == 2U);
    BOOST_CHECK(str1.find_first_of(str4, 3U) == 3U);
    BOOST_CHECK(str1.find_first_of("zza") == 0U);
    BOOST_CHECK(str1.find_first_of("zza", 0, 2) == Str::npos);
    BOOST_CHECK(str1.find_first_of('f', 2) == 5U);
    BOOST_CHECK(emptyStr.find_first_of(str4) == Str::npos);

    BOOST_CHECK(str1.find_first_not_of(str3) == 3U);
    BOOST_CHECK(str1.find_first_not_of("cabed", 0, 3) == 3U);
    BOOST_CHECK(str1.find_first_not_of("def", 3) == 6U);
    BOOST_CHECK(str1.find_first_not_of('a') == 1U);
    BOOST_CHECK(emptyStr.find_first_not_of(str3) == Str::npos);

    Str str5("bc");
    BOOST_CHECK(str1.find_last_of(str5) == 8U);
    BOOST_CHECK(str1.find_last_of(str5, 8U) == 8U);
    BOOST_CHECK(str1.find_last_of(str5, 7U) == 7U);
    BOOST_CHECK(str1.find_last_of(str5, 5U) == 2U);
    BOOST_CHECK(str1.find_last_of("abcdef", 4U, 3U) == 2U);
    BOOST_CHECK(str1.find_last_of("abcdef") == 8U);
    BOOST_CHECK(str1.find_last_of("def") == 5U);
    BOOST_CHECK(str1.find_last_of("a") == 6U);
    BOOST_CHECK(str1.find_last_of("a", 6U) == 6U);
    BOOST_CHECK(str1.find_last_of("a", 5U) == 0U);
    BOOST_CHECK(emptyStr.find_last_of(str5) == Str::npos);

    BOOST_CHECK(str1.find_last_not_of(str5) == 6U);
    BOOST_CHECK(str1.find_last_not_of(str5, 6U) == 6U);
    BOOST_CHECK(str1.find_last_not_of(str5, 3U) == 3U);
    BOOST_CHECK(str1.find_last_not_of(str5, 2U) == 0U);
    BOOST_CHECK(str1.find_last_not_of("abcdef", Str::npos, 3U) == 5U);
    BOOST_CHECK(str1.find_last_not_of("cdef", 5U) == 1U);
    BOOST_CHECK(str1.find_last_not_of("abcdef") == Str::npos);
    BOOST_CHECK(str1.find_last_not_of('a') == 8U);
    BOOST_CHECK(str1.find_last_not_of('c') == 7U);
    BOOST_CHECK(str1.find_last_not_of('a', 6U) == 5U);
    BOOST_CHECK(emptyStr.find_last_not_of(str5) == Str::npos);
}

BOOST_AUTO_TEST_CASE(test18) {
    typedef container::static_string<100> Str1;
    typedef container::static_string<50> Str2;
    typedef container::static_string<70> Str3;

    Str1 str1("abcd");
    Str2 str2("abce");
    Str3 str3(str1);

    BOOST_CHECK(str1 < str2);
    BOOST_CHECK(str1 <= str2);
    BOOST_CHECK(str2 > str1);
    BOOST_CHECK(str2 >= str1);
    BOOST_CHECK(str1 == str3);
    BOOST_CHECK(str1 <= str3);
    BOOST_CHECK(str1 >= str3);
}

BOOST_AUTO_TEST_CASE(test19) {
    typedef container::static_vector<int, 100> Vec1;
    typedef container::static_vector<int, 50> Vec2;

    Vec1 vec1;
    BOOST_CHECK(vec1.empty());
    BOOST_CHECK(vec1.size() == 0U);

    Vec1 vec2(20U, 5);
    BOOST_CHECK(vec2.size() == 20U);
    BOOST_CHECK(std::all_of(vec2.begin(), vec2.end(), [](int val) -> bool { return val == 5; }));

    vec1 = vec2;
    BOOST_CHECK(vec1 == vec2);

    Vec1 vec3(10U);
    BOOST_CHECK(vec3.size() == 10U);
    BOOST_CHECK(std::all_of(vec3.begin(), vec3.end(), [](int val) -> bool { return val == 0; }));

    static const int Data[] = {1, 2, 3, 4, 5, 6, 7};
    Vec1 vec4(std::begin(Data), std::end(Data));
    BOOST_CHECK(vec4.size() == std::extent<decltype(Data)>::value);
    BOOST_CHECK(std::equal(vec4.begin(), vec4.end(), std::begin(Data)));

    Vec2 vec5(vec4);
    BOOST_CHECK(vec5.size() == vec4.size());
    BOOST_CHECK(std::equal(vec4.begin(), vec4.end(), vec5.begin()));

    vec1 = vec5;
    BOOST_CHECK(std::equal(vec1.begin(), vec1.end(), vec5.begin()));

    Vec1 vec6 = {0, 1, 2, 3};
    BOOST_CHECK(vec6.size() == 4U);
    BOOST_CHECK(vec6[0] == 0);
    BOOST_CHECK(vec6[1] == 1);
    BOOST_CHECK(vec6[2] == 2);
    BOOST_CHECK(vec6[3] == 3);
}

BOOST_AUTO_TEST_CASE(test20) {
    typedef container::static_vector<std::string, 100> Vec1;
    typedef container::static_vector<std::string, 50> Vec2;

    Vec1 vec1;
    BOOST_CHECK(vec1.empty());
    BOOST_CHECK(vec1.size() == 0U);
    BOOST_CHECK(vec1.max_size() == 100U);
    BOOST_CHECK(vec1.capacity() == 100U);

    static const auto *Str = "hello";

    Vec1 vec2(20U, Str);
    BOOST_CHECK(vec2.size() == 20U);
    BOOST_CHECK(std::all_of(vec2.begin(), vec2.end(), [](Vec1::const_reference val) -> bool { return val == Str; }));

    Vec1 vec3(10U);
    BOOST_CHECK(vec3.size() == 10U);
    BOOST_CHECK(std::all_of(vec3.begin(), vec3.end(), [](Vec1::const_reference val) -> bool { return val.empty(); }));

    static const std::string Data[] = {"str1", "str2", "str3"};
    Vec1 vec4(std::begin(Data), std::end(Data));
    BOOST_CHECK(vec4.size() == std::extent<decltype(Data)>::value);
    BOOST_CHECK(std::equal(vec4.begin(), vec4.end(), std::begin(Data)));
    BOOST_CHECK(std::equal(std::begin(Data), std::end(Data), vec4.data()));

    Vec2 vec5(vec4);
    BOOST_CHECK(vec5.size() == vec4.size());
    BOOST_CHECK(std::equal(vec4.begin(), vec4.end(), vec5.begin()));

    Vec1 vec6 = {"str0", "str1", "str2", "str3"};
    BOOST_CHECK(vec6.size() == 4U);
    BOOST_CHECK(vec6[0] == "str0");
    BOOST_CHECK(vec6[1] == "str1");
    BOOST_CHECK(vec6[2] == "str2");
    BOOST_CHECK(vec6[3] == "str3");

    BOOST_CHECK(vec6.front() == "str0");
    BOOST_CHECK(vec6.back() == "str3");
    vec6.front() = "bla";
    vec6.back() = "hello";
    BOOST_CHECK(vec6[0] == "bla");
    BOOST_CHECK(vec6[3] == "hello");
    BOOST_CHECK(vec6[0] == vec6.front());
    BOOST_CHECK(vec6[3] == vec6.back());

    vec6.clear();
    BOOST_CHECK(vec6.size() == 0U);
    BOOST_CHECK(vec6.empty());
}

BOOST_AUTO_TEST_CASE(test21) {
    typedef container::static_vector<std::string, 100> Vec1;
    typedef container::static_vector<std::string, 50> Vec2;
    typedef container::static_vector<std::string, 70> Vec3;

    const Vec1 vec1 = {"str1", "str2", "str3"};

    Vec2 vec2;
    std::copy(vec1.begin(), vec1.end(), std::back_inserter(vec2));
    BOOST_CHECK(vec1 == vec2);

    Vec3 vec3;
    std::copy(vec2.crbegin(), vec2.crend(), std::back_inserter(vec3));
    BOOST_CHECK(vec3[0] == vec1[2]);
    BOOST_CHECK(vec3[1] == vec1[1]);
    BOOST_CHECK(vec3[2] == vec1[0]);
}

BOOST_AUTO_TEST_CASE(test22) {
    typedef container::static_vector<std::string, 100> Vec;

    Vec vec1 = {"str1", "str2", "str3", "str4"};

    Vec vec2(vec1);

    vec1.insert(vec1.end(), "str5");
    BOOST_CHECK(vec1.size() == vec2.size() + 1);
    BOOST_CHECK(std::equal(vec2.begin(), vec2.end(), vec1.begin()));
    BOOST_CHECK(vec1.back() == "str5");
    vec1.erase(vec1.end() - 1);
    BOOST_CHECK(vec1 == vec2);

    vec1.emplace_back("str5");
    BOOST_CHECK(vec1.size() == vec2.size() + 1);
    BOOST_CHECK(std::equal(vec2.begin(), vec2.end(), vec1.begin()));
    BOOST_CHECK(vec1.back() == "str5");
    vec1.erase(vec1.end() - 1);
    BOOST_CHECK(vec1 == vec2);

    Vec vec3 = {"str1", "str2", "bla", "bla", "bla", "str3", "str4"};
    vec1.insert(vec1.begin() + 2, 3, "bla");
    BOOST_CHECK(vec1 == vec3);
    vec1.erase(vec1.begin() + 2, vec1.end() - 2);
    BOOST_CHECK(vec1 == vec2);

    Vec vec4 = {"str1", "str2", "hello", "hello", "str3", "str4"};
    vec1.insert(vec1.begin() + 2, vec4.begin() + 2, vec4.begin() + 4);
    BOOST_CHECK(vec1 == vec4);
    vec1.erase(vec1.begin() + 2, vec1.end() - 2);
    BOOST_CHECK(vec1 == vec2);

    Vec vec5 = {"str1", "dead", "beef", "str2", "str3", "str4"};
    vec1.insert(vec1.begin() + 1, vec5.begin() + 1, vec5.begin() + 3);
    BOOST_CHECK(vec1 == vec5);
    vec1.erase(vec1.begin() + 1, vec1.end() - 3);
    BOOST_CHECK(vec1 == vec2);

    vec1.insert(vec1.begin() + 1, {"dead", "beef"});
    BOOST_CHECK(vec1 == vec5);
    vec1.erase(vec1.begin() + 1, vec1.end() - 3);
    BOOST_CHECK(vec1 == vec2);

    vec1.emplace(vec1.begin() + 1, "beef");
    vec1.emplace(vec1.begin() + 1, "dead");
    BOOST_CHECK(vec1 == vec5);
    vec1.erase(vec1.begin() + 1, vec1.end() - 3);
    BOOST_CHECK(vec1 == vec2);

    while (!vec1.empty()) {
        vec1.pop_back();
    }

    Vec vec6 = {
        "str1",
        "str2",
    };
    vec1 = vec2;
    vec1.resize(2U);
    BOOST_CHECK(vec1 == vec6);

    Vec vec7 = {"str1", "str2", std::string(), std::string()};
    vec1.resize(4U);
    BOOST_CHECK(vec1.size() == 4U);
    BOOST_CHECK(vec1 == vec7);
}

BOOST_AUTO_TEST_CASE(test23) {
    typedef container::static_vector<std::string, 100> Vec1;
    typedef container::static_vector<std::string, 50> Vec2;

    const Vec1 origVec1 = {"str1", "str2", "str3"};

    Vec1 vec1 = origVec1;

    const Vec2 origVec2 = {"hello1", "hello2", "hello3", "hello4"};

    Vec2 vec2 = origVec2;

    BOOST_CHECK(vec1 == origVec1);
    BOOST_CHECK(vec2 == origVec2);
    BOOST_CHECK(vec1 != vec2);

    BOOST_CHECK(vec2 < vec1);
    BOOST_CHECK(vec2 <= vec1);
    BOOST_CHECK(vec1 > vec2);
    BOOST_CHECK(vec1 >= vec2);

    BOOST_CHECK(vec1 <= origVec1);
    BOOST_CHECK(vec1 >= origVec1);

    BOOST_CHECK(vec2 <= origVec2);
    BOOST_CHECK(vec2 >= origVec2);

    std::swap(vec1, vec2);
    BOOST_CHECK(vec1 == origVec2);
    BOOST_CHECK(vec2 == origVec1);
    BOOST_CHECK(vec1 != vec2);
}

BOOST_AUTO_TEST_CASE(test24) {
    typedef container::static_string<20> StaticStr;
    typedef container::static_vector<std::uint8_t, 20> StaticVec;
    typedef container::static_vector<char, 20> StaticVecChar;

    static_assert(types::detail::string_has_push_back<std::string>::value,
                  "std::string must have push_back");

    static_assert(types::detail::string_has_push_back<StaticStr>::value,
                  "static_string must have push_back");

    static_assert(
        !types::detail::string_has_push_back<container::string_view>::value,
        "string_view doesn't have push_back");

    static_assert(types::detail::string_has_assign<std::string>::value,
                  "std::string must have "
                  "assign");

    static_assert(types::detail::string_has_assign<StaticStr>::value,
                  "static_string must have "
                  "assign");

    static_assert(
        !types::detail::string_has_assign<container::string_view>::value,
        "string_view doesn't have assign");

    static_assert(types::detail::vector_has_assign<std::vector<std::uint8_t>>::value,
                  "std::vector doesn't have assign");

    static_assert(types::detail::vector_has_assign<StaticVec>::value,
                  "static_vector doesn't "
                  "have assign");

    static_assert(!types::detail::vector_has_assign<
                      container::array_view<std::uint8_t>>::value,
                  "array_view has assign");

    static_assert(has_member_function_reserve<std::string>::value, "std::string must have reserve");
    static_assert(has_member_function_reserve<StaticStr>::value, "static_string must have reserve");
    static_assert(has_member_function_reserve<StaticVec>::value, "static_vector must have reserve");
    static_assert(!has_member_function_reserve<container::string_view>::value,
                  "string_view mustn't have reserve");

    static_assert(has_member_function_clear<std::string>::value, "std::string must have clear");
    static_assert(has_member_function_clear<StaticStr>::value, "static_string must have clear");
    static_assert(has_member_function_clear<StaticVec>::value, "static_vector must have clear");
    static_assert(!has_member_function_clear<container::string_view>::value,
                  "string_view mustn't have clear");

    static_assert(has_member_function_remove_suffix<container::string_view>::value,
                  "string_view must have remove_suffix");

    static_assert(std::is_base_of<container::detail::static_vector_casted<char, unsigned char, 20>,
                                  StaticVecChar>::value,
                  "Wrong base class");

    static_assert(std::is_base_of<container::detail::static_vector_generic<unsigned char, 20>,
                                  StaticVecChar>::value,
                  "Wrong base class");
}

BOOST_AUTO_TEST_CASE(test25) {
    container::string_view str("hello");
    BOOST_CHECK(str.size() == 5U);
    BOOST_CHECK(!str.empty());
    BOOST_CHECK(std::string(str.begin(), str.end()) == "hello");
    BOOST_CHECK(std::string(str.rbegin(), str.rend()) == "olleh");
    BOOST_CHECK(str[1] == 'e');
    BOOST_CHECK(str[4] == 'o');
    BOOST_CHECK(str.front() == 'h');
    BOOST_CHECK(str.back() == 'o');
    BOOST_CHECK(str.compare("hemmo") < 0);
    BOOST_CHECK(str.compare("hello") == 0);
    BOOST_CHECK(str.compare("hello1") < 0);
    BOOST_CHECK(0 < str.compare("hell"));
    BOOST_CHECK(0 < str.compare("hebbol"));
    BOOST_CHECK(str.find("el") == 1);
    BOOST_CHECK(str.find("le") == container::string_view::npos);
    BOOST_CHECK(str.find('l', 3) == 3);
    BOOST_CHECK(str.find_first_of("ollh") == 0);
    BOOST_CHECK(str.find_last_of("llh") == 3);
    BOOST_CHECK(str.find_first_not_of("hel") == 4);
    BOOST_CHECK(str.find_last_not_of("hlo") == 1);

    auto *beg = &str[0];
    str.remove_prefix(1);
    BOOST_CHECK(str.size() == 4U);
    BOOST_CHECK(str == "ello");
    BOOST_CHECK(beg + 1 == str.data());
    str.remove_suffix(2);
    BOOST_CHECK(str.size() == 2U);
    BOOST_CHECK(str == "el");
    BOOST_CHECK(beg + 1 == str.data());
}

BOOST_AUTO_TEST_SUITE_END()
