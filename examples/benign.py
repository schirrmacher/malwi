import argparse
import logging
import sys


def setup_logging():
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )


def greet(name: str):
    logging.info("Preparing greeting...")
    print(f"Hello, {name}!")
    logging.info("Greeting completed.")


def main():
    setup_logging()
    parser = argparse.ArgumentParser(description="A simple Hello World script.")
    parser.add_argument("--name", type=str, default="World", help="The name to greet.")
    args = parser.parse_args()

    try:
        greet(args.name)
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
