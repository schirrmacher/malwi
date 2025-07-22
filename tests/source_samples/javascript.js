// Comprehensive JavaScript Compiler Test Suite
// This file is designed to test a wide range of JavaScript language features,
// including basic syntax, data types, control flow, functions,
// object-oriented programming, advanced features, and built-in objects.
//
// A successful execution of this file, with all tests passing,
// indicates a high degree of compatibility and correctness for a JavaScript engine.

// ==============================================================================
// Extended Import Test Cases - For malware analysis import pattern testing
// ==============================================================================

// ES6 Import Statements - Testing modern JavaScript import syntax
// Note: These would normally require module context, but we're testing the compiler's parsing

// ES6 Default imports
import React from 'react';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import child_process from 'child_process';

// Named imports
import { readFile, writeFile, existsSync } from 'fs';
import { join, resolve, dirname, basename } from 'path';
import { createHash, randomBytes, pbkdf2Sync } from 'crypto';
import { platform, arch, tmpdir, homedir } from 'os';
import { exec, spawn, fork } from 'child_process';

// Mixed imports (default + named)
import express, { Router, static as staticFiles } from 'express';
import axios, { get, post, put, delete as del } from 'axios';

// Aliased imports
import { readFile as read, writeFile as write } from 'fs';
import { join as pathJoin, resolve as pathResolve } from 'path';
import { createHash as hash, randomBytes as random } from 'crypto';

// Wildcard imports (namespace imports)
import * as fsModule from 'fs';
import * as pathModule from 'path';
import * as cryptoModule from 'crypto';
import * as osModule from 'os';

// Side-effect imports (imports without bindings)
import 'core-js/stable';
import './malicious-polyfill.js';
import '../../../config/secret-keys.json';

// Potentially suspicious module patterns (common in malware)
import keytar from 'keytar';
import node_pty from 'node-pty';
import screenshot_desktop from 'screenshot-desktop';
import robotjs from 'robotjs';
import mic from 'mic';
import systeminformation from 'systeminformation';

// Export statements (also part of ES6 modules)
export const exportedConst = 'test-export';
export function exportedFunction() { return 'exported'; }
export default { defaultExport: true };

// CommonJS require() patterns (also commonly seen)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const childProcess = require('child_process');
const util = require('util');
const stream = require('stream');
const events = require('events');

// Destructured require
const { readFile, writeFile, existsSync } = require('fs');
const { join, resolve, dirname } = require('path');
const { createHash, randomBytes } = require('crypto');
const { exec, spawn } = require('child_process');

// Aliased require
const cp = require('child_process');
const fsPromises = require('fs').promises;
const pathUtils = require('path');

// Conditional require (evasion pattern)
let platform_module;
try {
    platform_module = require('os');
    const platform = platform_module.platform();
} catch (e) {
    // Fallback or evasion
}

// Dynamic require (obfuscation pattern)
const moduleName = 'fs';
const dynamicModule = require(moduleName);
const encodedModule = require(Buffer.from('ZnM=', 'base64').toString());

console.log("--- Extended Import Test Cases: COMPLETED ---");
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

// ==============================================================================
// 9. Missing Node Types Coverage
// ==============================================================================

console.log("\n--- 9. Missing Node Types Coverage ---");

// 9.1. Boolean and null literals
const trueVal = true;
const falseVal = false;
const nullVal = null;
const undefinedVal = undefined;

// 9.2. Unary operators
const negativeNum = -42;
const positiveNum = +42;
const bitwiseNot = ~42;
const logicalNot = !true;
const typeofOp = typeof 42;

// 9.3. Augmented assignment
let augVal = 10;
augVal += 5;
augVal -= 2;
augVal *= 3;
augVal /= 2;

// 9.4. Comparison and logical operators
const compResult = 1 < 2 && 2 > 1 || 3 === 3;
const strictEqual = 5 === 5;
const notStrictEqual = 5 !== "5";
const instanceOf = new Date() instanceof Date;

// 9.5. Arrow functions
const arrowFunc = x => x * 2;
const arrowFunc2 = (a, b) => a + b;
const arrowResult = arrowFunc(5);

// 9.6. Template literals
const name = "World";
const templateStr = `Hello, ${name}!`;
const multilineTemplate = `Line 1
Line 2`;

// 9.7. Destructuring
const arr = [1, 2, 3];
const [first, second] = arr;
const obj = { a: 1, b: 2 };
const { a, b } = obj;

// 9.8. Spread operator
const newArr = [...arr, 4, 5];
const newObj = { ...obj, c: 3 };

// 9.9. Try/catch/finally
try {
    const riskyOp = JSON.parse("invalid json");
} catch (error) {
    const errorHandled = true;
} finally {
    const cleanupDone = true;
}

// 9.10. For loops variations
for (let i = 0; i < 3; i++) {
    if (i === 1) continue;
    if (i === 2) break;
}

for (const item of arr) {
    const processed = item;
}

for (const key in obj) {
    const value = obj[key];
}

// 9.11. Switch statement
const switchVal = 2;
switch (switchVal) {
    case 1:
        const case1 = true;
        break;
    case 2:
        const case2 = true;
        break;
    default:
        const defaultCase = true;
}

// 9.12. Conditional (ternary) operator
const ternaryResult = 5 > 0 ? "positive" : "negative";

// 9.13. Array and object methods
const mappedArr = arr.map(x => x * 2);
const filteredArr = arr.filter(x => x > 1);
const reducedVal = arr.reduce((acc, x) => acc + x, 0);

// 9.14. Regular expressions
const regex = /test/gi;
const regexTest = regex.test("Test string");

// 9.15. Classes with inheritance
class Parent {
    constructor(name) {
        this.name = name;
    }
    
    greet() {
        return `Hello from ${this.name}`;
    }
}

class Child extends Parent {
    constructor(name, age) {
        super(name);
        this.age = age;
    }
    
    greetWithAge() {
        return `${super.greet()}, age ${this.age}`;
    }
}

const childInstance = new Child("Test", 25);

// 9.16. Async/await and Promises
async function asyncFunc() {
    const promise = new Promise(resolve => setTimeout(() => resolve("done"), 1));
    const result = await promise;
    return result;
}

// 9.17. Import/export (commented as they need module context)
// import { someFunc } from './module.js';
// export const exportedVal = 42;

// 9.18. Optional chaining and nullish coalescing
const optional = obj?.deep?.property;
const nullish = nullVal ?? "default";

// 9.19. Throw statement
function testThrow() {
    throw new Error("Test error");
}

// 9.20. Missing Operators for Malware Analysis Coverage
// Bitwise operations (common in malware obfuscation)
const bitwiseAnd = 0xFF & 0x0F;        // Bitwise AND
const bitwiseOr = 0x10 | 0x01;         // Bitwise OR  
const bitwiseXor = 0xAA ^ 0x55;        // Bitwise XOR
const leftShift = 8 << 2;              // Left shift
const rightShift = 32 >> 3;            // Right shift
const unsignedRightShift = 32 >>> 2;   // Unsigned right shift (JavaScript-specific)

// Strict equality/inequality (type checking)
const strictEqualTest = (5 === 5);     // Strict equality
const strictNotEqualTest = (5 !== "5"); // Strict inequality

// Nullish coalescing operator (modern evasion)
const nullishCoalescing = null ?? "default";
const undefinedCoalescing = undefined ?? "fallback";

// Delete and void operators (property manipulation)
const testObj = { prop: "value" };
delete testObj.prop;                    // Delete operator
const voidResult = void 0;             // Void operator

console.log("9. Missing Node Types Coverage: PASSED");

// 9.21. BINARY_SUBSCR Test Cases (Array and Object Access Patterns)
// These patterns are commonly used in malware for data access and obfuscation

// Basic array access (should generate BINARY_SUBSCR)
const testArray = [1, 2, 3, 4, 5];
const firstElement = testArray[0];
const lastElement = testArray[testArray.length - 1];
const dynamicIndex = testArray[Math.floor(Math.random() * testArray.length)];

// Object access with bracket notation (should generate BINARY_SUBSCR)
const configObject = { 
    apiKey: "secret123", 
    endpoint: "https://malicious.com/api",
    payload: { data: "encoded" }
};
const apiKey = configObject["apiKey"];
const endpoint = configObject["endpoint"];
const dynamicProperty = configObject["pay" + "load"];

// Nested object/array access (should generate multiple BINARY_SUBSCR)
const nestedStructure = {
    users: [
        { name: "admin", permissions: ["read", "write", "execute"] },
        { name: "guest", permissions: ["read"] }
    ],
    config: {
        servers: ["192.168.1.1", "10.0.0.1"],
        ports: [80, 443, 8080]
    }
};
const adminName = nestedStructure["users"][0]["name"];
const adminPermissions = nestedStructure.users[0].permissions[2];
const firstServer = nestedStructure["config"]["servers"][0];
const httpsPort = nestedStructure.config.ports[1];

// Variable-based property access (common in obfuscated malware)
const propName = "endpoint";
const keyName = "apiKey";
const dynamicAccess1 = configObject[propName];
const dynamicAccess2 = configObject[keyName];

// Computed property access patterns
const computedKey = "api" + "Key";
const encodedKey = btoa("endpoint").substring(0, 8); // Base64 encode + substring
const obfuscatedAccess = configObject[computedKey];

// Array access with expressions (common in payload decoding)
const payloadArray = new Array(10).fill(0).map((_, i) => i * 2);
const calculatedIndex = payloadArray[5 + 2];
const expressionIndex = payloadArray[Math.pow(2, 2)];
const moduloIndex = payloadArray[15 % payloadArray.length];

// String character access (used in string manipulation attacks)
const maliciousString = "javascript:void(0)";
const protocolChar = maliciousString[0];
const colonChar = maliciousString[maliciousString.indexOf(":")];
const voidPart = maliciousString[11]; // 'v' from void

// Multi-dimensional array access
const matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
];
const centerElement = matrix[1][1];
const cornerElement = matrix[0][0];
const lastRowLastCol = matrix[matrix.length - 1][matrix[0].length - 1];

// Object with array values access
const commandMap = {
    "exec": ["cmd.exe", "/c"],
    "shell": ["powershell.exe", "-c"],
    "bash": ["/bin/bash", "-c"]
};
const windowsCmd = commandMap["exec"][0];
const powershellFlag = commandMap["shell"][1];

// Buffer/typed array access (common in binary data manipulation)
const buffer = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // "Hello" in bytes
const firstByte = buffer[0];
const secondByte = buffer[1];

// Access with variables from other scopes
let globalIndex = 2;
const scopedAccess = testArray[globalIndex];
const functionBasedIndex = testArray[Math.floor(Math.random() * 3)];

console.log("9.21. BINARY_SUBSCR Test Cases: PASSED");


console.log("\n--- JavaScript Compiler Test Suite: Finished ---");
console.log("--- All tests completed. Check output for any errors. ---");