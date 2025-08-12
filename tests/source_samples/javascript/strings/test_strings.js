// JavaScript String Operations Test Suite

// String literals (various quote types)
const singleQuoted = 'Hello world';
const doubleQuoted = "Hello world";
const backtickString = `Template literal`;

// Template literals with expressions
const name = "Alice";
const age = 30;
const templateBasic = `Hello, ${name}!`;
const templateExpression = `${name} is ${age} years old`;
const templateComplex = `Next year ${name} will be ${age + 1}`;
const templateMultiline = `Line 1
Line 2
Line 3`;

// String concatenation
const concatPlus = "Hello" + " " + "world";
const concatTemplate = `${"Hello"} ${"world"}`;
const concatMethod = "Hello".concat(" ", "world");

// String indexing and access
const text = "Hello, World!";
const firstChar = text[0];
const lastChar = text[text.length - 1];
const charAt = text.charAt(0);
const charCodeAt = text.charCodeAt(0);

// String slicing (substring methods)
const substring = text.substring(7, 12); // "World"
const substr = text.substr(7, 5);        // "World" (deprecated)
const slice = text.slice(7, 12);         // "World"
const sliceNegative = text.slice(-6, -1); // "World"

// String case methods
const upperCase = "hello".toUpperCase();
const lowerCase = "HELLO".toLowerCase();
const localeUpper = "hello".toLocaleUpperCase();
const localeLower = "HELLO".toLocaleLowerCase();

// String trimming
const stripped = "  hello  ".trim();
const leftStripped = "  hello  ".trimStart(); // or trimLeft()
const rightStripped = "  hello  ".trimEnd();  // or trimRight()

// String search methods
const textSearch = "The quick brown fox";
const indexOf = textSearch.indexOf("quick");
const lastIndexOf = textSearch.lastIndexOf("o");
const includes = textSearch.includes("brown");
const startsWith = textSearch.startsWith("The");
const endsWith = textSearch.endsWith("fox");

// String replacement
const replaceResult = textSearch.replace("fox", "dog");
const replaceAll = "hello hello hello".replaceAll("hello", "hi");
const replaceRegex = textSearch.replace(/o/g, "0");

// String splitting and joining
const csvData = "apple,banana,cherry";
const splitResult = csvData.split(",");
const joinResult = ["a", "b", "c"].join(" | ");
const splitLimit = "a-b-c-d-e".split("-", 3);

// String matching with regex
const pattern = /\d+/g;
const textWithNumbers = "I have 10 apples and 5 oranges";
const matches = textWithNumbers.match(pattern);
const matchAll = [...textWithNumbers.matchAll(/\d+/g)];
const search = textWithNumbers.search(/\d+/);

// String testing methods
const isDigit = /^\d+$/.test("123");
const isAlpha = /^[a-zA-Z]+$/.test("abc");
const isAlphaNum = /^[a-zA-Z0-9]+$/.test("abc123");

// String padding
const padStart = "5".padStart(3, "0");     // "005"
const padEnd = "5".padEnd(3, "0");         // "500"
const padStartSpace = "hello".padStart(10); // "     hello"

// String repetition
const repeated = "Ha".repeat(5);
const dashes = "-".repeat(40);

// String comparison
const str1 = "apple";
const str2 = "banana";
const comparison = str1 < str2; // Lexicographic comparison
const equality = str1 === "apple";
const caseInsensitive = str1.toLowerCase() === "APPLE".toLowerCase();

// String encoding/decoding
const encoded = encodeURIComponent("Hello World!");
const decoded = decodeURIComponent(encoded);
const encodedURI = encodeURI("https://example.com/path with spaces");
const decodedURI = decodeURI(encodedURI);

// String escaping
const escapedQuotes = "She said \"Hello\" to me";
const escapedNewline = "Line 1\nLine 2\nLine 3";
const escapedTab = "Column1\tColumn2\tColumn3";
const escapedBackslash = "Path: C:\\folder\\file.txt";
const escapedUnicode = "Unicode: \u0041\u0042\u0043"; // ABC

// String from character codes
const fromCharCode = String.fromCharCode(65, 66, 67); // "ABC"
const fromCodePoint = String.fromCodePoint(0x1F44D);  // 👍

// String normalization
const accented = "café";
const normalized = accented.normalize('NFD');
const composed = normalized.normalize('NFC');

// String localization
const localeCompare = "a".localeCompare("b");
const localeCompareOptions = "Äpfel".localeCompare("Zebra", 'de', { numeric: true });

// Raw strings (using String.raw)
const rawString = String.raw`Raw string with \n no escaping`;
const rawPath = String.raw`C:\Users\name\file.txt`;

// String iteration
const iterableString = "hello";
const charArray = [...iterableString];
const forOfChars = [];
for (const char of iterableString) {
    forOfChars.push(char);
}

// String methods chaining
const chained = "  Hello World  "
    .trim()
    .toLowerCase()
    .replace("world", "javascript")
    .split(" ")
    .join("-");

// String with special characters
const specialChars = "Special: !@#$%^&*()_+-=[]{}|;':\",./<>?";
const hasSpecial = /[^a-zA-Z0-9]/.test(specialChars);

// String coercion
const numberToString = String(123);
const booleanToString = String(true);
const objectToString = String({name: "test"});
const arrayToString = String([1, 2, 3]);

// String interpolation with tagged templates
function highlight(strings, ...values) {
    return strings.reduce((result, string, i) => {
        return result + string + (values[i] ? `**${values[i]}**` : '');
    }, '');
}
const highlighted = highlight`Hello ${name}, you are ${age} years old!`;

// String methods with arrays
const words = ["hello", "world", "javascript"];
const uppercaseWords = words.map(word => word.toUpperCase());
const longWords = words.filter(word => word.length > 5);
const joinedWords = words.join(" ");

// JSON string operations
const obj = {name: "Alice", age: 30};
const jsonString = JSON.stringify(obj);
const parsedObject = JSON.parse(jsonString);

// String builder pattern (array join for performance)
const parts = [];
parts.push("Hello");
parts.push(" ");
parts.push("World");
const built = parts.join("");

// String validation patterns
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const phonePattern = /^\(\d{3}\) \d{3}-\d{4}$/;
const isValidEmail = emailPattern.test("user@example.com");
const isValidPhone = phonePattern.test("(555) 123-4567");

console.log("String operations test completed");