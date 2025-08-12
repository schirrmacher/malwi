// JavaScript Advanced Features Test Suite

// Promises
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const promise = new Promise((resolve, reject) => {
    setTimeout(() => resolve("Success!"), 10);
});

promise
    .then(result => result.toUpperCase())
    .then(upper => console.log(upper))
    .catch(error => console.error(error))
    .finally(() => console.log("Cleanup"));

// Promise methods
Promise.all([delay(10), delay(20)])
    .then(() => console.log("All done"));

Promise.race([delay(10), delay(20)])
    .then(() => console.log("First done"));

// Async/await
async function asyncFunction() {
    try {
        const result = await delay(10);
        return "Async complete";
    } catch (error) {
        console.error(error);
    }
}

// Generators
function* fibonacci() {
    let a = 0, b = 1;
    while (true) {
        yield a;
        [a, b] = [b, a + b];
    }
}

const fib = fibonacci();
fib.next().value; // 0
fib.next().value; // 1
fib.next().value; // 1

// Iterators
const customIterator = {
    [Symbol.iterator]() {
        let step = 0;
        return {
            next() {
                step++;
                if (step <= 3) {
                    return { value: step, done: false };
                }
                return { done: true };
            }
        };
    }
};

for (const value of customIterator) {
    // iterates 1, 2, 3
}

// Destructuring
const [a, b, ...rest] = [1, 2, 3, 4, 5];
const {x, y, ...others} = {x: 1, y: 2, z: 3, w: 4};

// Nested destructuring
const {
    user: {
        name,
        address: { city }
    }
} = {
    user: {
        name: "Alice",
        address: { city: "NYC", zip: "10001" }
    }
};

// Spread operator
const arr1 = [1, 2], arr2 = [3, 4];
const combined = [...arr1, ...arr2];
const obj1 = {a: 1}, obj2 = {b: 2};
const merged = {...obj1, ...obj2};

// Template literals
const name = "World";
const multiline = `Line 1
Line 2
Line 3`;
const tagged = String.raw`Path: C:\new\folder`;

// Symbol
const sym1 = Symbol('id');
const sym2 = Symbol('id');
console.log(sym1 === sym2); // false

const obj = {
    [sym1]: "value1",
    [Symbol.for('global')]: "value2"
};

// Proxy
const target = { value: 42 };
const handler = {
    get(target, prop) {
        console.log(`Getting ${prop}`);
        return target[prop];
    },
    set(target, prop, value) {
        console.log(`Setting ${prop} to ${value}`);
        target[prop] = value;
        return true;
    }
};
const proxy = new Proxy(target, handler);
proxy.value; // triggers get
proxy.value = 100; // triggers set

// Reflect
Reflect.get(target, 'value');
Reflect.set(target, 'value', 200);
Reflect.has(target, 'value');

console.log("Advanced features test completed");