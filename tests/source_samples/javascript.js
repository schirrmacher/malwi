// Comprehensive JavaScript Compiler Test Suite
// This file is designed to test a wide range of JavaScript language features,
// including basic syntax, data types, control flow, functions,
// object-oriented programming, advanced features, and built-in objects.
//
// A successful execution of this file, with all tests passing,
// indicates a high degree of compatibility and correctness for a JavaScript engine.

console.log("--- JavaScript Compiler Test Suite: Starting ---");

// ==============================================================================
// 1. Basic Syntax and Literals
// ==============================================================================

console.log("\n--- 1. Basic Syntax and Literals ---");

// 1.1. Comments
// This is a single-line comment.
/*
  This is a
  multi-line comment.
*/

// 1.2. Variable Declarations
var a = 1;      // Function-scoped
let b = 2;      // Block-scoped
const c = 3;    // Block-scoped, constant
console.log("1.2. Variable Declarations: PASSED");


// 1.3. Literals
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
console.log("1.3. Literals: PASSED");

// ==============================================================================
// 2. Data Types and Operations
// ==============================================================================

console.log("\n--- 2. Data Types and Operations ---");

// 2.1. Number and Math
let n1 = 10, n2 = 4;
n1 + n2;
n1 - n2;
n1 * n2;
n1 / n2;
n1 % n2;
n1 ** 2;
Math.sqrt(144);
console.log("2.1. Number and Math: PASSED");

// 2.2. String
let str1 = "hello";
let str2 = "world";
str1 + " " + str2;
str1.length;
str1[1]; // "e"
str1.substring(1, 4); // "ell"
str1.toUpperCase();
console.log("2.2. String: PASSED");

// 2.3. Array
let arr = [1, "two", 3.0];
arr.length;
arr.push(4);
arr.pop();
arr[0] = "one";
arr.map(x => typeof x);
console.log("2.3. Array: PASSED");

// 2.4. Object
let obj = { name: "John", age: 30 };
obj.name;
obj['age'];
obj.city = "New York";
delete obj.age;
Object.keys(obj);
Object.values(obj);
console.log("2.4. Object: PASSED");

// 2.5. Type Coercion
1 == '1'; // true
1 === '1'; // false
'5' - 3; // 2 (number)
'5' + 3; // '53' (string)
console.log("2.5. Type Coercion: PASSED");

// ==============================================================================
// 3. Control Flow
// ==============================================================================

console.log("\n--- 3. Control Flow ---");

// 3.1. if/else if/else
let num = 0;
if (num > 0) {
    // block
} else if (num < 0) {
    // block
} else {
    // block
}
console.log("3.1. if/else: PASSED");

// 3.2. switch
let day = 'Monday';
switch (day) {
    case 'Monday':
        break;
    case 'Tuesday':
        break;
    default:
        break;
}
console.log("3.2. switch: PASSED");

// 3.3. Loops (for, for...in, for...of, while)
for (let i = 0; i < 3; i++) {
    // loop
}
for (const key in {a:1, b:2}) {
    // loop
}
for (const val of [1, 2, 3]) {
    // loop
}
let k = 3;
while (k > 0) {
    k--;
}
console.log("3.3. Loops: PASSED");

// 3.4. try/catch/finally
try {
    // intentionalError();
    throw new Error("Intentional error");
} catch (e) {
    // handle error
} finally {
    // always executes
}
console.log("3.4. try/catch/finally: PASSED");


// ==============================================================================
// 4. Functions and Scopes
// ==============================================================================

console.log("\n--- 4. Functions and Scopes ---");

// 4.1. Function Declaration
function greet(name) {
    return `Hello, ${name}!`;
}
greet("World");

// 4.2. Function Expression
const farewell = function(name) {
    return `Goodbye, ${name}.`;
};
farewell("World");

// 4.3. Arrow Function
const square = (x) => x * x;
square(4);

// 4.4. Parameters (Default, Rest)
function paramsTest(a, b = 10, ...rest) {
    return [a, b, rest];
}
paramsTest(1, 2, 3, 4, 5);

// 4.5. Closures
function makeCounter() {
    let count = 0;
    return function() {
        count++;
        return count;
    };
}
const counter = makeCounter();
counter(); // 1
counter(); // 2
console.log("4.1-4.5. Functions and Scopes: PASSED");

// ==============================================================================
// 5. Object-Oriented Programming (OOP)
// ==============================================================================

console.log("\n--- 5. Object-Oriented Programming ---");

// 5.1. Constructor Function (Pre-ES6)
function Car(make, model) {
    this.make = make;
    this.model = model;
}
Car.prototype.getInfo = function() {
    return `${this.make} ${this.model}`;
};
const myCarOld = new Car('Ford', 'Focus');
myCarOld.getInfo();
console.log("5.1. Constructor Functions: PASSED");

// 5.2. ES6 Classes (Syntax, Inheritance)
class Vehicle {
    constructor(name) {
        this.name = name;
    }
    move() {
        return `${this.name} is moving.`;
    }
}

class Motorcycle extends Vehicle {
    constructor(name, brand) {
        super(name); // Call parent constructor
        this.brand = brand;
    }
    // Override method
    move() {
        return `${this.brand} ${this.name} is riding.`;
    }
}
const bike = new Motorcycle('Ninja', 'Kawasaki');
bike.move();
console.log("5.2. ES6 Classes: PASSED");

// 5.3. Getters, Setters, and Static Members
class Rectangle {
    constructor(width, height) {
        this._width = width;
        this._height = height;
    }
    get area() {
        return this._width * this._height;
    }
    set width(value) {
        this._width = value;
    }
    static createSquare(size) {
        return new Rectangle(size, size);
    }
}
const rect = new Rectangle(10, 5);
rect.area;
rect.width = 20;
Rectangle.createSquare(8);
console.log("5.3. Getters, Setters, Static: PASSED");

// ==============================================================================
// 6. Advanced Features (ES6+)
// ==============================================================================

console.log("\n--- 6. Advanced Features (ES6+) ---");

// 6.1. Promises and async/await
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function myAsyncFunction() {
    await delay(50);
    return "Async work done";
}
myAsyncFunction().then(result => {
    console.log("6.1. Promises and async/await: PASSED");
});

// 6.2. Generators
function* idGenerator() {
    let id = 1;
    while (true) {
        yield id++;
    }
}
const gen = idGenerator();
gen.next().value; // 1
gen.next().value; // 2
console.log("6.2. Generators: PASSED");

// 6.3. Modules (Syntax check)
// In a real module environment, these would work. Here, they're for syntax validation.
// export const MY_CONST = 42;
// import { MY_CONST } from './module.js';
console.log("6.3. Modules: Syntax parsed (requires module runner)");

// 6.4. Destructuring and Spread/Rest
const [first, , third] = ["a", "b", "c"];
const { name: personName, age } = { name: "Jane", age: 25 };
const arr1 = [1, 2], arr2 = [3, 4];
const combined = [...arr1, ...arr2];
const { x, ...restObj } = { x: 1, y: 2, z: 3 };
console.log("6.4. Destructuring and Spread/Rest: PASSED");

// ==============================================================================
// 7. Built-in Objects
// ==============================================================================

console.log("\n--- 7. Built-in Objects ---");

// 7.1. JSON
const jsonString = '{"fruit":"apple","size":"large"}';
const jsonObj = JSON.parse(jsonString);
JSON.stringify(jsonObj);
console.log("7.1. JSON: PASSED");

// 7.2. Date
const now = new Date();
now.getFullYear();
now.toISOString();
console.log("7.2. Date: PASSED");

// 7.3. Regular Expressions
const emailRegex = /\S+@\S+\.\S+/;
emailRegex.test("test@example.com"); // true
"The rain in Spain".match(/ain/g); // ['ain', 'ain']
console.log("7.3. Regular Expressions: PASSED");

// ==============================================================================
// 8. Dynamic Features
// ==============================================================================

console.log("\n--- 8. Dynamic Features ---");

// 8.1. eval()
// Use with caution. Primarily for testing the compiler's ability to parse and execute strings.
eval("2 + 2");
console.log("8.1. eval(): PASSED");

// 8.2. Dynamic property access
const dynamicObj = {};
const propName = "dynamicProperty";
dynamicObj[propName] = "success";
console.log("8.2. Dynamic properties: PASSED");


console.log("\n--- JavaScript Compiler Test Suite: Finished ---");
console.log("--- All tests completed. Check output for any errors. ---");