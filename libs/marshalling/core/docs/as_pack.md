# Marshalling Library As Pack Examples

Marhalling Library can be simply used for packing value from one type to another and 
for changing endianness by the way.

To read from one type and write to another type variable we will use such funtion:

```cpp
template<typename TField>
static TField read_from_field(const char *buf, std::size_t size,
                               nil::marshalling::status_type expectedStatus
                               = nil::marshalling::status_type::success){

    typedef TField field_type;
    field_type field;

    auto iter = buf;
    auto status = field.read(iter, size);
    BOOST_CHECK(status == expectedStatus);

    if (status != nil::marshalling::status_type::success) {
        return field;
    }

    auto diff = static_cast<std::size_t>(std::distance(buf, iter));
    BOOST_CHECK_EQUAL(field.length(), diff);

    std::unique_ptr<char[]> outDataBuf(new char[diff]);
    auto writeIter = &outDataBuf[0];

    status = field.write(writeIter, diff);
    BOOST_CHECK(status == nil::marshalling::status_type::success);
    BOOST_CHECK(std::equal(buf, buf + diff, static_cast<const char *>(&outDataBuf[0])));

    auto writeDiff = static_cast<std::size_t>(std::distance(&outDataBuf[0], writeIter));
    BOOST_CHECK_EQUAL(field.length(), writeDiff);
    BOOST_CHECK_EQUAL(diff, writeDiff);
    return field;
}
```

Using this function we can easily pack data from one type to another:

```cpp
using big_endian_array_type = 
    nil::marshalling::types::array_list<
        nil::marshalling::field_type<nil::marshalling::option::big_endian>,
        std::uint32_t
    >;

    static const char Buf[] = {0x01, 0x02, 0x03, 0x04, 
                               0x05, 0x06, 0x07, 0x08, 
                               0x09, 0x0a, 0x0b, 0x0c, 
                               0x0d, 0x0e, 0x0f, 0x10};

    static const std::size_t BufSize = std::extent<decltype(Buf)>::value;
    big_endian_array_type be_vector = read_from_field<big_endian_array_type>(Buf, BufSize);

    std::vector<std::uint32_t> be_vector_value = be_vector.value();
```

Now we have vector `be_vector_value` of `std::uint32_t` values in `big_endian` : {`0x01020304`, `0x05060708`, `0x090a0b0c`, `0x0d0e0f10`}.

