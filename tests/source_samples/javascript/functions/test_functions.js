// JavaScript Functions and Scopes Test Suite

// Function Declaration
function greet(name) {
    return `Hello, ${name}!`;
}
greet("World");

// Function Expression
const farewell = function(name) {
    return `Goodbye, ${name}.`;
};
farewell("World");

// Arrow Function
const square = (x) => x * x;
square(4);

// Arrow function variations
const noParams = () => "no params";
const oneParam = x => x * 2;
const multiParams = (a, b) => a + b;
const blockBody = (x) => {
    const doubled = x * 2;
    return doubled;
};

// Parameters (Default, Rest)
function paramsTest(a, b = 10, ...rest) {
    return [a, b, rest];
}
paramsTest(1, 2, 3, 4, 5);

// Destructured parameters
function destructuredParams({name, age}) {
    return `${name} is ${age}`;
}
destructuredParams({name: "Alice", age: 30});

// Closures
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

// IIFE (Immediately Invoked Function Expression)
(function() {
    const privateVar = "hidden";
})();

// Function with keyword arguments pattern
function keywordArgs(options) {
    const {name = "default", value = 0, flag = false} = options || {};
    return {name, value, flag};
}
keywordArgs({name: "test", value: 42});

// Generators
function* idGenerator() {
    let id = 1;
    while (true) {
        yield id++;
    }
}
const gen = idGenerator();
gen.next().value; // 1
gen.next().value; // 2

// Async functions
async function fetchData() {
    return new Promise(resolve => {
        setTimeout(() => resolve("data"), 10);
    });
}

async function processData() {
    const data = await fetchData();
    return data;
}

// Function constructors
const add = new Function('a', 'b', 'return a + b');
add(2, 3);

// Bind, call, apply
function showThis() {
    return this;
}
const obj = { value: 42 };
showThis.call(obj);
showThis.apply(obj);
const boundFunc = showThis.bind(obj);
boundFunc();

console.log("Functions and scopes test completed");