# Marshalling Library Quick Examples
Below are quick examples on how to define fields as well as messages using
Marshalling library. For proper and full tutorial please refer to proper documentation.

## Defining fields_type
Almost every field definition type receives its base class as a template
parameter. This base class is expected to be a variant of **nil::marshalling::field_type** with
endian information.
```cpp
using MyFieldBase = nil::marshalling::field_type<nil::marshalling::option::big_endian>;
```

Now the definition of simple 2 byte unsigned integer value field looks like this:
```cpp
using MyIntField = nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>;
```

The definition of unsigned integer with 3 bytes serialization length:
```cpp
using My3ByteIntField = 
    nil::marshalling::types::int_value<
        MyFieldBase, // big endian serialization 
        std::uint32_t, // store as 4 byte unsigned integer
        nil::marshalling::option::fixed_length<3> // serialise using only 3 bytes
    >;
```

Definition of the year value, serialized using only 1 byte as an offset from
year 2000, and default constructed as year 2017:
```cpp
using MyYearField = 
    nil::marshalling::types::int_value<
        MyFieldBase, // big endian serialization
        std::int16_t, // store as 2 byte value
        nil::marshalling::option::fixed_length<1>, // serialise using only 1 byte
        nil::marshalling::option::num_value_ser_offset<-2000> // add (-2000) before serialization and 
                                                // subtruct (-2000) after deserialization
        nil::marshalling::option::default_num_value<2017> // construct with default value 2017
    >;
```

Variant length (Base-128) integer value:
```cpp
using MyVarLengthField = 
    nil::marshalling::types::int_value<
        MyFieldBase, // big endian serialization
        std::uint32_t, // store as 4 bytes value
        nil::marshalling::option::var_length<1, 4> // 1 to 4 bytes serialization length.
    >;
```

Enum values are similar to integer ones:
```cpp
enum class MyEnum : std::uint8_t // Serialise using 1 byte
{
    Value1,
    Value2,
    Value3,
    NumOfValues
};

using MyEnumField = 
    nil::marshalling::types::enum_value<
        MyFieldBase, // big endian serialization
        MyEnum, // use MyEnum as storage type
        nil::marshalling::option::valid_num_value_range<0, (int)MyEnum::NumOfValues - 1> // provide range of valid values
    >;
```

2 bytes bitmask value:
```cpp
struct MyBitmaskField : public 
    nil::marshalling::types::bitmask_value<
        MyFieldBase, // big endian serialization
        nil::marshalling::types::fixed_length<2> // serialise using 2 bytes
        bitmask_reserved_bits<0xfff0> // Specify reserved bits 
    >
{
    MARSHALLING_BITMASK_BITS_SEQ(name1, name2, name3, name4); // provide names for bits for convenient access
}
```

Bitfields:
```cpp
struct MyBitfield : public
    nil::marshalling::types::bitfield<
        MyFieldBase,
        std::tuple<
            nil::marshalling::types::int_value<MyFieldBase, std::uint8_t, nil::marshalling::option::fixed_bit_length<2> >, // 2 bits value
            nil::marshalling::types::bitmask_value<MyFieldBase, nil::marshalling::option::fixed_bit_length<3> >, // 3 bits value
            nil::marshalling::types::enum_value<MyFieldBase, MyEnum, nil::marshalling::option::fixed_bit_length<3> > // 3 bits value
        >
    >
{
    MARSHALLING_FIELD_MEMBERS_ACCESS(value1, value2, value3); // names for member fields for convenient access
};
```

Simple raw data list:
```cpp
using MyRawDataList = 
    nil::marshalling::types::array_list<
        MyFieldBase,
        std::uint8_t
    >;
```

Raw data list with 2 byte size prefix:
```cpp
using MyRawDataList2 = 
    nil::marshalling::types::array_list<
        MyFieldBase,
        std::uint8_t,
        nil::marshalling::option::sequence_size_field_prefix<
            nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>
        >
    >;
```

Size prefixed list of complex (bundle) elements:
```cpp
using MyComplexList = 
    nil::marshalling::types::array_list<
        MyFieldBase,
        nil::marshalling::types::bundle<
            MyFieldBase,
            std::tuple<
                nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>, // 2 bytes int
                nil::marshalling::types::enum_value<MyFieldBase, MyEnum> // 1 byte enum
            >
        >,
        nil::marshalling::option::sequence_size_field_prefix<
            nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>
        >
    >;
```

String with 1 byte size prefix:
```cpp
using MyString = 
    nil::marshalling::types::string<
        MyFieldBase,
        nil::marshalling::option::sequence_size_field_prefix<
            nil::marshalling::types::int_value<MyFieldBase, std::uint8_t>
        >        
    >
```

Optional 2 byte integer, default constructed as "missing".:
```cpp
using MyOptInt = 
    nil::marshalling::types::optional<
        nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>,
        nil::marshalling::option::default_optional_mode<nil::marshalling::types::optional_mode::missing>        
    >
```

# Defining Messages
Usually the message IDs are numeric values specified using an enum
```cpp
// Message ID
enum msg_id : std::uint16_t
{
    MsgId_Msg1,
    MsgId_Msg2,
    MsgId_Msg3,
    ...
};
```

The message message definition will usually like like this:
```cpp
// fields_type used by Message1 (defined below)
using Message1Fields = 
    std::tuple<
        MyIntField,  
        MyBitmaskField
        MyRawDataList2
    >;
    
// The definition of Message1 message
template <typename TMsgBase> // Interface class passed as a template parameter
class Message1 : public
    nil::marshalling::message_base<
        TMsgBase,
        nil::marshalling::option::static_num_id_impl<MsgId_Msg1>, // numeric message ID
        nil::marshalling::option::fields_impl<Message1Fields>, // provide message fields
        nil::marshalling::option::msg_type<Message1<TMsgBase> > // specify exact type of the message
    >
{
    // Provide names of the fields for convenient access
    MARSHALLING_MSG_FIELDS_ACCESS(field1, field2, field3);
};
```

The definition of the message contents is common for any application. The 
generated code depends on the used message interface classes.

# Defining Interface
The interface definition is application specific. Every application defines
what polymorphic interface every message needs to define and implement:
```cpp
using App1Interface =
    nil::marshalling::message<
        nil::marshalling::option::big_endian, // Use big endian for serialization
        nil::marshalling::option::msg_type<msg_id>, // Provide type used for message ID
        nil::marshalling::option::id_info_interface, // Support polymorphic retreival of message ID
        nil::marshalling::option::read_iterator<const std::uint8_t*>, // Support polymorphic read using "const std::uint8_t*" as iterator
        nil::marshalling::option::write_iterator<std::uint8_t*>, // Support polymorphic write using "std::uint8_t*" as iterator
        nil::marshalling::option::length_info_interface, // Support polymorphic retrieval of serialization length
        nil::marshalling::option::valid_check_interface, // Support polymorphic contents validity check
        nil::marshalling::option::handler<MyHandler> // Support dispatch to handling object of "MyHandler" type
    >;
```

Some other application may define different interface:
```cpp
using App2Interface =
    nil::marshalling::message<
        nil::marshalling::option::big_endian, // Use big endian for serialization
        nil::marshalling::option::msg_type<msg_id>, // Provide type used for message ID
        nil::marshalling::option::id_info_interface, // Support polymorphic retreival of message ID
        nil::marshalling::option::read_iterator<const std::uint8_t*>, // Support polymorphic read using "const std::uint8_t*" as iterator
        nil::marshalling::option::write_iterator<std::back_insert_itetrator<std::vector<std::uint8_t> > >, 
                                                          // Support polymorphic write using
                                                          // "std::back_insert_itetrator<std::vector<std::uint8_t> > >" as iterator
        nil::marshalling::option::handler<MyOtherHandler> // Support dispatch to handling object of "MyOtherHandler" type
    >;
```

Note that definition of **Message1** class remains unchanged, every application
passes its chosen interface to implement the required functionality.

In app1:
```cpp
using Msg1 = Message1<App1Interface>; // will implement all the virtual functions required by app1
```

In app2:
```cpp
using Msg1 = Message1<App2Interface>; // will implement all the virtual functions required by app2
```

## Defining Transport Frames
The transport frames definition is also flexible and assembled out of layers.
For example, simple frame of just 2 bytes size followed by 2 byte message ID
will look like this:
```cpp
// Define field used to (de)serialise message id (see definition of msg_id enum earlier)
using MsgIdField = nil::marshalling::types::enum_value<MyFieldBase, msg_id>

// Define field used to (de)serialise remaining length of the message:
using MsgSizeField = nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>

// Define transport stack by wrapping "layers"
using Stack = 
    nil::marshalling::protocol::MsgSizeLayer< // The SIZE 
        MsgSizeField,
        nil::marshalling::option::MsgIdLayer< // The ID 
            MsgIdField,
            nil::marshalling::protocol::MsgDataLayer<> // The PAYLOAD
        >
    >;
```

The more complex transport consisting of SYNC, SIZE, ID, PAYLOAD, and CHECKSUM
may look like this:
```cpp

// Define field used to (de)serialise message id (see definition of msg_id enum earlier)
using MsgIdField = nil::marshalling::types::enum_value<MyFieldBase, msg_id>

// Define field used to (de)serialise remaining length of the message:
using MsgSizeField = nil::marshalling::types::int_value<MyFieldBase, std::uint16_t>

// Define checksum value field
using ChecksumField =
    nil::marshalling::types::int_value<
        MyFieldBase,
        std::uint16_t
    >;

// Define field used as synchronisation prefix
using SyncField =
    nil::marshalling::types::int_value<
        MyFieldBase,
        std::uint16_t,
        nil::marshalling::option::default_num_value<0xabcd>,
        nil::marshalling::option::valid_num_value_range<0xabcd, 0xabcd>
    >;

// Define transport stack by wrapping "layers"
using Stack = 
    nil::marshalling::protocol::SyncPrefixLayer< // The SYNC
        SyncField,
        nil::marshalling::protocol::ChecksumLayer // The CHECKSUM
            ChecksumField,
            nil::marshalling::protocol::checksum::crc_ccitt, // Use CRC-CCITT calculation
            nil::marshalling::protocol::MsgSizeLayer< // The SIZE 
                MsgSizeField,
                nil::marshalling::option::MsgIdLayer< // The ID 
                    MsgIdField,
                    nil::marshalling::protocol::MsgDataLayer<> // The PAYLOAD
                >
            >
        >
    >;
```

