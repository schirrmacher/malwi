// JavaScript Built-in Objects Test Suite

// JSON
const jsonString = '{"fruit":"apple","size":"large"}';
const jsonObj = JSON.parse(jsonString);
JSON.stringify(jsonObj);
JSON.stringify(jsonObj, null, 2); // pretty print

// Date
const now = new Date();
now.getFullYear();
now.getMonth();
now.getDate();
now.toISOString();
now.toLocaleDateString();
Date.now(); // timestamp

// Regular Expressions
const emailRegex = /\S+@\S+\.\S+/;
emailRegex.test("test@example.com"); // true
"The rain in Spain".match(/ain/g); // ['ain', 'ain']
"Hello World".replace(/World/, "JavaScript");
"a,b,c".split(/,/); // ['a', 'b', 'c']

// Math object
Math.PI;
Math.E;
Math.random();
Math.max(1, 2, 3);
Math.min(1, 2, 3);
Math.pow(2, 3);
Math.log(10);
Math.sin(Math.PI / 2);

// Array built-in methods
Array.isArray([1, 2, 3]);
Array.from("hello"); // ['h', 'e', 'l', 'l', 'o']
Array.of(1, 2, 3); // [1, 2, 3]
[1, 2, 3].join("-"); // "1-2-3"
[3, 1, 4, 2].sort();
[1, 2, 3].reverse();

// String built-in methods
"hello".charAt(0);
"hello".charCodeAt(0);
"hello".indexOf("ll");
"hello".lastIndexOf("l");
"hello".slice(1, 4);
"hello".substring(1, 4);
"HELLO".toLowerCase();
"hello".toUpperCase();
"  hello  ".trim();
"hello".repeat(3);
"hello".startsWith("he");
"hello".endsWith("lo");
"hello".includes("ell");
"hello".padStart(10, "*");
"hello".padEnd(10, "*");

// Number built-in methods
Number.parseInt("123");
Number.parseFloat("123.45");
Number.isInteger(123);
Number.isFinite(123);
Number.isNaN(NaN);
(123.456).toFixed(2);
(123.456).toPrecision(4);
(255).toString(16); // "ff"

// Object built-in methods
Object.create(null);
Object.assign({}, {a: 1}, {b: 2});
Object.keys({a: 1, b: 2});
Object.values({a: 1, b: 2});
Object.entries({a: 1, b: 2});
Object.freeze({a: 1});
Object.seal({a: 1});
Object.getOwnPropertyNames({a: 1});
Object.getOwnPropertyDescriptor({a: 1}, 'a');

// Global functions
parseInt("123");
parseFloat("123.45");
isNaN(NaN);
isFinite(123);
encodeURI("https://example.com/path with spaces");
decodeURI("https://example.com/path%20with%20spaces");
encodeURIComponent("name=value&other=test");
decodeURIComponent("name%3Dvalue%26other%3Dtest");

console.log("Built-in objects test completed");