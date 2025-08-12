// JavaScript Data Types and Operations Test Suite

// Number and Math
let n1 = 10, n2 = 4;
n1 + n2;
n1 - n2;
n1 * n2;
n1 / n2;
n1 % n2;
n1 ** 2;
Math.sqrt(144);
Math.floor(3.7);
Math.ceil(3.2);
Math.round(3.5);
Math.abs(-5);

// String operations
let str1 = "hello";
let str2 = "world";
str1 + " " + str2;
str1.length;
str1[1]; // "e"
str1.substring(1, 4); // "ell"
str1.toUpperCase();
str2.toLowerCase();
"  spaced  ".trim();
"comma,separated".split(",");

// Array operations
let arr = [1, "two", 3.0];
arr.length;
arr.push(4);
arr.pop();
arr[0] = "one";
arr.map(x => typeof x);
arr.filter(x => typeof x === "number");
arr.reduce((acc, val) => acc + val, 0);

// Object operations
let obj = { name: "John", age: 30 };
obj.name;
obj['age'];
obj.city = "New York";
delete obj.age;
Object.keys(obj);
Object.values(obj);
Object.entries(obj);

// Type Coercion
1 == '1'; // true
1 === '1'; // false
'5' - 3; // 2 (number)
'5' + 3; // '53' (string)
Boolean(0); // false
Boolean(""); // false
Boolean("hello"); // true
Number("123"); // 123
String(123); // "123"

// Array methods
const numbers = [1, 2, 3, 4, 5];
numbers.forEach(n => n * 2);
numbers.map(n => n * 2);
numbers.filter(n => n > 2);
numbers.find(n => n > 3);
numbers.findIndex(n => n > 3);
numbers.some(n => n > 4);
numbers.every(n => n > 0);
numbers.includes(3);
numbers.indexOf(3);

// Object methods
const person = { name: "Alice", age: 25 };
const hasName = 'name' in person;
const hasOwn = person.hasOwnProperty('age');
const merged = Object.assign({}, person, { city: "NYC" });
const spread = { ...person, city: "NYC" };

console.log("Data types and operations test completed");