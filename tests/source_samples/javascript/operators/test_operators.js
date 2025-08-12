// JavaScript Operators and Binary Operations Test Suite

// Arithmetic operators
let a = 10, b = 3;
a + b;
a - b;
a * b;
a / b;
a % b;
a ** 2; // Exponentiation

// Unary operators
const negativeNum = -42;
const positiveNum = +42;
const bitwiseNot = ~42;
const logicalNot = !true;
const typeofOp = typeof 42;
const voidOp = void 0;

// Increment/decrement
let counter = 0;
counter++;
++counter;
counter--;
--counter;

// Bitwise operations
const bitwiseAnd = 0xFF & 0x0F;        // Bitwise AND
const bitwiseOr = 0x10 | 0x01;         // Bitwise OR  
const bitwiseXor = 0xAA ^ 0x55;        // Bitwise XOR
const leftShift = 8 << 2;              // Left shift
const rightShift = 32 >> 3;            // Right shift
const unsignedRightShift = -1 >>> 1;   // Unsigned right shift

// Comparison operators
5 < 10;
5 > 3;
5 <= 5;
10 >= 10;
5 == "5";   // loose equality
5 === 5;    // strict equality
5 != "5";   // loose inequality  
5 !== "5";  // strict inequality

// Logical operators
true && false;
true || false;
!true;

// Nullish coalescing
null ?? "default";
undefined ?? "fallback";
0 ?? "zero is not nullish";

// Optional chaining
const obj = { a: { b: { c: 1 } } };
obj?.a?.b?.c;
obj?.x?.y?.z;
obj.method?.();

// Augmented assignment
let augVal = 10;
augVal += 5;
augVal -= 2;
augVal *= 3;
augVal /= 2;
augVal %= 3;
augVal **= 2;
augVal &= 0xFF;
augVal |= 0x0F;
augVal ^= 0xAA;
augVal <<= 2;
augVal >>= 1;
augVal >>>= 1;

// BINARY_SUBSCR test cases (array/object access)
const testArray = [1, 2, 3, 4, 5];
const firstElement = testArray[0];
const lastElement = testArray[testArray.length - 1];
const dynamicIndex = testArray[Math.floor(Math.random() * testArray.length)];

// Object subscript access
const configObject = { 
    apiKey: "secret123", 
    endpoint: "https://example.com/api",
    nested: { data: "value" }
};
const apiKey = configObject["apiKey"];
const endpoint = configObject["endpoint"];
const dynamicProp = configObject["nested"]["data"];

// STORE_SUBSCR test cases (assignment)
const storeObj = {};
const storeArr = [];

// Basic assignments
storeObj["key1"] = "value1";
storeObj['key2'] = 'value2';
storeObj[`key3`] = `value3`;

// Dynamic key assignment
const storeKey = "dynamicKey";
storeObj[storeKey] = "dynamicValue";

// Array assignments
storeArr[0] = "first";
storeArr[1] = "second";
storeArr[10] = "sparse";

// Computed property assignment
const prefix = "computed";
storeObj[prefix + "_key"] = "computed value";
storeObj[`${prefix}_template`] = "template value";

// String operators
"Hello" + " " + "World";
"abc" < "def";
"test".localeCompare("test");

// in operator
"key1" in storeObj;
0 in storeArr;
"toString" in {};

// delete operator
delete storeObj.key1;
delete storeArr[0];

console.log("Operators and binary operations test completed");