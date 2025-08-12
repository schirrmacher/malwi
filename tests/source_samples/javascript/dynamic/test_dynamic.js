// JavaScript Dynamic Features Test Suite

// eval() - dynamic code execution
eval("2 + 2");
const code = "console.log('Dynamic execution')";
eval(code);

// Dynamic property access
const dynamicObj = {};
const propName = "dynamicProperty";
dynamicObj[propName] = "success";

// Computed property names
const key = "computed";
const obj = {
    [key]: "value",
    [key + "2"]: "value2",
    [`${key}3`]: "value3"
};

// Dynamic method calls
const methodName = "toString";
const result = obj[methodName]();

// Function constructor
const add = new Function('a', 'b', 'return a + b');
add(5, 3);

// Dynamic imports (ES2020)
// import('./module.js').then(module => {
//     module.default();
// });

// Global object access
const globalObj = (function() { return this; })() || globalThis;
globalObj.dynamicGlobal = "I'm global";

// with statement (deprecated but still valid)
const withObj = { x: 10, y: 20 };
with (withObj) {
    // x and y are accessible directly here
    const sum = x + y;
}

// in operator
const hasProperty = 'propName' in dynamicObj;
const hasMethod = 'toString' in obj;

// delete operator
delete dynamicObj[propName];
delete obj.computed;

// typeof operator
typeof 42; // "number"
typeof "hello"; // "string"
typeof true; // "boolean"
typeof undefined; // "undefined"
typeof null; // "object" (historical bug)
typeof {}; // "object"
typeof []; // "object"
typeof function() {}; // "function"

// instanceof operator
const arr = [];
arr instanceof Array; // true
arr instanceof Object; // true

// Object property descriptors
Object.defineProperty(obj, 'readOnly', {
    value: 42,
    writable: false,
    enumerable: true,
    configurable: false
});

// Dynamic getter/setter
const dynObj = {
    _value: 0,
    get value() {
        return this._value;
    },
    set value(v) {
        this._value = v;
    }
};

// Global variables in different contexts
var globalVar = "I am a global var";
globalThis.explicitGlobal = "Explicit global";

function modifyGlobals() {
    globalVar = "Modified";
    implicitGlobal = "Created implicitly";
    globalThis.anotherGlobal = "Another one";
}

modifyGlobals();

// void operator
void 0; // undefined
void(0); // undefined

console.log("Dynamic features test completed");