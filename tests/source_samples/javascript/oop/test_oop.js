// JavaScript Object-Oriented Programming Test Suite

// Constructor Function (Pre-ES6)
function Car(make, model) {
    this.make = make;
    this.model = model;
}
Car.prototype.getInfo = function() {
    return `${this.make} ${this.model}`;
};
const myCarOld = new Car('Ford', 'Focus');
myCarOld.getInfo();

// ES6 Classes
class Vehicle {
    constructor(name) {
        this.name = name;
    }
    move() {
        return `${this.name} is moving.`;
    }
}

// Class inheritance
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

// Getters, Setters, and Static Members
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

// Private fields (ES2022)
class BankAccount {
    #balance = 0;
    
    constructor(initialBalance) {
        this.#balance = initialBalance;
    }
    
    getBalance() {
        return this.#balance;
    }
    
    deposit(amount) {
        this.#balance += amount;
    }
}
const account = new BankAccount(100);
account.getBalance();
account.deposit(50);

// Object creation patterns
const obj1 = {};
const obj2 = new Object();
const obj3 = Object.create(null);
const obj4 = Object.create(Object.prototype);

// Prototype manipulation
function Animal(name) {
    this.name = name;
}
Animal.prototype.speak = function() {
    return `${this.name} makes a sound`;
};

function Dog(name, breed) {
    Animal.call(this, name);
    this.breed = breed;
}
Dog.prototype = Object.create(Animal.prototype);
Dog.prototype.constructor = Dog;
Dog.prototype.bark = function() {
    return "Woof!";
};

const dog = new Dog("Max", "Labrador");
dog.speak();
dog.bark();

// instanceof checks
console.log(dog instanceof Dog);
console.log(dog instanceof Animal);
console.log(dog instanceof Object);

console.log("Object-oriented programming test completed");