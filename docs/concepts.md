# Concepts # {#component_concepts}

A ```circuit``` is defined by ```Blueprint``` instance and ```Blueprint assignment table``` instance. It consist of one or multiple components putted on these two. While ```Blueprint``` holds information about the circuit itself, its gates, constraints and other fixed extensions, ```Blueprint assignment table``` contains public and private assignments needed by zk-SNARK system.

## Blueprint 

## PLONK component concept ## {##plonk_component_concepts}

### PLONK Component interface ###

A ```Component``` ```X``` is a state-less object with following static functions to operate with it:

* ```X::allocate_rows``` - allocates required amount of rows in the given ```Arithmetization table```. The amount of required rows amount is constexpr for the particular component;
* ```X::generate_gates``` - generates gate expressions and puts these on the given ```Blueprint```;
* ```X::generate_copy_constraints``` - generates copy constraints and puts them on the given ```Blueprint```;
* ```X::generate_lookup_constraints``` - generates copy constraints and puts them on the given ```Blueprint```;
* ```X::generate_assignments``` - evaluates assignments values and puts them on the given ```Blueprint assignment table```;

Note that ```generate_gates/copy_constraints/lookup_constraints``` can modify of the ```Blueprint public assignment table``` setting ```Constant```, ```Selector``` or ```Public input``` columns, but they don't use or set data of the ```Blueprint private assignment table```. The only function managing ```Blueprint private assignment table``` is ```generate_assignments``` - which, by the way, also can modify the ```Blueprint public assignment table```. In short, it looks like that:

|Function                   |Required Input                    |Can modify |
|-----------------------------|------------------------|-----------------------|
|```X::allocate_rows```       |```Blueprint```         |```Blueprint```|
|```X::generate_gates```, ```X::generate_copy_constraints```, ```X::generate_lookup_constraints```      |```Blueprint```, ```Blueprint public assignment table```, ```Component init params (a.k.a public input)```, ```component start row```          |```Blueprint```, ```Blueprint public assignment table```|
|```X::generate_assignments```  |```Blueprint public assignment table```, ```Blueprint private assignment table```, ```Component init params (a.k.a public input)```, ```Component assignment params (a.k.a private input)```, ```component start row```        |```Blueprint public assignment table```, ```Blueprint private assignment table```|

The process of adding a component is following:

1. (Optional) Get ```component``` start row by calling ```allocate_rows```. If the ```component``` is used as part of other ```component``` logic, it's not neccessary to call the function, because needed rows are allocated by the master ```component```.
2. Set all the gates and constraints on the ```Blueprint``` by calling ```generate_gates/copy_constraints/lookup_constraints```. ```Blueprint public assignment table``` can also be modified in proccess of these funcitons working.
3. Set all the private assignments on the ```Blueprint private assignment table``` table by calling ```generate_assignments```. ```Blueprint public assignment table``` can also be modified in proccess of this funciton working.