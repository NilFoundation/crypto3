---
description: Compile time evaluations for matrix, vectors & scalars
---

# matrix/vectors

{% hint style="info" %}
Matrix/Vector/Scalar are designed to be compile time computations using `constexpr`

These classes can be used in run-time as well but are not optimised yet.
{% endhint %}

## Matrix

`matrix` is a generic type which allows creation of 2D matrices. The type also supports common transformations which can be applied to matrices ex: transpose, matrix multiplication etc.

Matrix is defined under the namespace `nil::crypto3::algebra` and header need to be included ex: `<nil/crypto3/algebra/matrix/matrix.hpp>`

### Usage

#### Example#1

```cpp
constexpr matrix<double, 3, 3> m1 = {1., 2., 3., 4., 5., 6., 7., 8., 9.};
constexpr matrix m2 = {{{1., 2.}}};
```

Apart from basic matrix transformation, there is also support provided for addition, multiplication and division between matrices and matrices and scalars. Please see references/code for full set of functionality.



## Vectors

`vector` is a generic type which allows creation of 1D arrays of fixed size (TODO check).

vector is defined under the namespace `nil::crypto3::algebra` and header need to be included : `nil/crypto3/algebra/vector/vector.hpp`

Utility functions defined which allow for operations such as slicing, concat , rotate. see `vector/utility.hpp`

Math operations can be performed on vectors such as square root , element wise complex conjugate etc. See `vector/math.hpp`

### Usage

#### Example#1

```cpp
vector {1, 2, 3}
```



There are utility functions provided to perform compile time evaluations like sqrt , exponentiation under `scalar/math.hpp`&#x20;
