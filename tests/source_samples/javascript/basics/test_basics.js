// JavaScript Basic Syntax and Literals Test Suite

// Comments
// This is a single-line comment.
/*
  This is a
  multi-line comment.
*/

// Variable Declarations
var a = 1;      // Function-scoped
let b = 2;      // Block-scoped
const c = 3;    // Block-scoped, constant

// Literals
const stringLiteral = "hello";
const templateLiteral = `world with value ${b}`;
const numberLiteral = 123.45;
const bigIntLiteral = 9007199254740991n;
const booleanLiteral = true;
const nullLiteral = null;
const undefinedLiteral = undefined;
const objectLiteral = { key: "value" };
const arrayLiteral = [1, 2, 3];
const regexLiteral = /ab+c/i;

// Basic assignments
let x = 5;
let y = 10;
let z = x + y;

// Multiple variable declarations
let d, e, f;
d = 1; e = 2; f = 3;

// Destructuring assignment
const [first, second] = [1, 2];
const {name, age} = {name: "John", age: 30};

console.log("Basic syntax and literals test completed");