// JavaScript Control Flow Test Suite

// if/else if/else
let num = 0;
if (num > 0) {
    // positive
} else if (num < 0) {
    // negative
} else {
    // zero
}

// Nested if
let x = 5, y = 10;
if (x > 0) {
    if (y > 0) {
        // both positive
    }
}

// switch statement
let day = 'Monday';
switch (day) {
    case 'Monday':
        break;
    case 'Tuesday':
        break;
    default:
        break;
}

// Switch with fall-through
const value = 2;
switch (value) {
    case 1:
    case 2:
    case 3:
        // handles 1, 2, or 3
        break;
    default:
        // other values
}

// for loop
for (let i = 0; i < 3; i++) {
    // loop body
}

// for...in loop (objects)
for (const key in {a:1, b:2}) {
    // iterate over object keys
}

// for...of loop (iterables)
for (const val of [1, 2, 3]) {
    // iterate over array values
}

// while loop
let k = 3;
while (k > 0) {
    k--;
}

// do...while loop
let count = 0;
do {
    count++;
} while (count < 3);

// break and continue
for (let i = 0; i < 10; i++) {
    if (i === 2) continue;
    if (i === 5) break;
}

// Labeled statements
outer: for (let i = 0; i < 3; i++) {
    for (let j = 0; j < 3; j++) {
        if (i === 1 && j === 1) {
            break outer;
        }
    }
}

// try/catch/finally
try {
    throw new Error("Intentional error");
} catch (e) {
    // handle error
} finally {
    // always executes
}

// Multiple catch (proposed feature, using if/else pattern)
try {
    // risky code
} catch (e) {
    if (e instanceof TypeError) {
        // handle TypeError
    } else if (e instanceof ReferenceError) {
        // handle ReferenceError
    } else {
        // handle other errors
    }
}

// Conditional (ternary) operator
const result = num > 0 ? "positive" : "non-positive";

// Nullish coalescing
const value1 = null ?? "default";
const value2 = undefined ?? "fallback";

// Optional chaining
const obj = { a: { b: { c: 1 } } };
const deepValue = obj?.a?.b?.c;
const missingValue = obj?.x?.y?.z;

console.log("Control flow test completed");