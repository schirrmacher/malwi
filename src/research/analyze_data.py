import re
import os
import sys
import json
import nltk
import argparse

import pandas as pd
from collections import Counter
from nltk.util import ngrams
from nltk.corpus import stopwords

try:
    nltk.data.find("corpora/stopwords")
except LookupError:
    print("NLTK 'stopwords' corpus not found. Downloading...")
    try:
        nltk.download("stopwords", quiet=True)  # Download quietly
        print("Download complete.")
    except Exception as e:
        print(f"Error downloading NLTK 'stopwords': {e}", file=sys.stderr)
        print(
            "Please try running 'import nltk; nltk.download('stopwords')' manually in a Python interpreter.",
            file=sys.stderr,
        )
        sys.exit(1)


def preprocess_text(text):
    """
    Cleans and tokenizes the input text using whitespace tokenization.
    Removes punctuation and removes stop words, keeping original casing.
    Returns a list of tokens.
    """
    if not isinstance(text, str):
        return []  # Return empty list for non-string input

    text = re.sub(r"[^\w\s]", "", text)  # Remove punctuation
    tokens = text.split()  # Tokenize by whitespace
    stop_words = set(stopwords.words("english"))
    # Filter out stop words (case-insensitive check)
    tokens = [word for word in tokens if word.lower() not in stop_words]
    return tokens


def get_ngram_counts(tokens_list, n):
    """
    Generates n-grams from a list of token lists and counts their frequencies.
    """
    all_ngrams = []
    for tokens in tokens_list:
        # Ensure there are enough tokens to form an n-gram
        if len(tokens) >= n:
            all_ngrams.extend(list(ngrams(tokens, n)))
    ngram_counts = Counter(all_ngrams)
    return ngram_counts


def run_ngram_analysis(args):
    """
    Performs the n-gram analysis based on the provided arguments.
    """
    print(
        f"Analyzing n-grams (n={args.ngram_size}) from column '{args.text_column}' in {args.input_file}..."
    )

    # Load data (common step, could be moved outside if needed frequently)
    try:
        df = pd.read_csv(args.input_file)
    except FileNotFoundError:
        print(f"Error: Input file not found at {args.input_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading CSV file: {e}", file=sys.stderr)
        sys.exit(1)

    # Validate text column
    if args.text_column not in df.columns:
        print(
            f"Error: Text column '{args.text_column}' not found in the input file.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("Preprocessing text...")
    df["tokens"] = df[args.text_column].apply(
        lambda x: preprocess_text(x) if pd.notna(x) else []
    )

    print(f"Calculating {args.ngram_size}-grams...")
    ngram_counts = get_ngram_counts(
        df["tokens"].tolist(), args.ngram_size
    )  # Pass list of lists

    if not ngram_counts:
        print(
            f"No n-grams of size {args.ngram_size} found in the dataset after preprocessing.",
            file=sys.stderr,
        )
        return  # Exit the function gracefully

    ngram_df = pd.DataFrame.from_records(
        ngram_counts.most_common(args.limit), columns=["ngram", "count"]
    )
    ngram_df["ngram"] = ngram_df["ngram"].apply(lambda x: " ".join(x))

    pd.options.display.max_colwidth = None
    pd.options.display.max_rows = None
    pd.options.display.max_columns = None
    pd.options.display.width = None

    print(f"\nTop {args.limit} most common {args.ngram_size}-grams:")
    print(ngram_df.to_string(index=False))  # Use to_string for better console output

    if args.output_mapping:
        print(f"\nGenerating n-gram mapping for top {args.limit}...")
        ngram_mapping = {}

        for _, row in ngram_df.iterrows():
            ngram_key = row["ngram"]  # Already a string
            ngram_tuple = tuple(ngram_key.split())  # Recreate tuple if needed for logic

            if len(set(token.lower() for token in ngram_tuple)) == 1:
                mapped_value = f"{ngram_tuple[0].upper()}_{len(ngram_tuple)}"
            else:
                mapped_value = "_".join(token.upper() for token in ngram_tuple) + "_X"
            ngram_mapping[ngram_key] = mapped_value

        try:
            with open(args.output_mapping, "w") as f:
                json.dump(ngram_mapping, f, indent=4)
            print(f"N-gram mapping saved to {args.output_mapping}")
        except Exception as e:
            print(
                f"Error saving n-gram mapping to {args.output_mapping}: {e}",
                file=sys.stderr,
            )


def run_stats_analysis(args):
    """
    Calculates and displays statistics about the text column.
    """
    print(
        f"Analyzing statistics for column '{args.text_column}' in {args.input_file}..."
    )

    try:
        df = pd.read_csv(args.input_file)
    except FileNotFoundError:
        print(f"Error: Input file not found at {args.input_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading CSV file: {e}", file=sys.stderr)
        sys.exit(1)

    if args.text_column not in df.columns:
        print(
            f"Error: Text column '{args.text_column}' not found in the input file.",
            file=sys.stderr,
        )
        sys.exit(1)

    word_counts = df[args.text_column].apply(
        lambda x: len(x.split()) if isinstance(x, str) else 0
    )

    if word_counts.empty:
        print("No text data found to analyze.", file=sys.stderr)
        return

    average_words = word_counts.mean()
    max_words = word_counts.max()
    total_lines = len(df)
    lines_with_text = len(word_counts[word_counts > 0])

    print("\nText Column Statistics:")
    print(f"  Total lines in CSV: {total_lines}")
    print(f"  Lines with text in '{args.text_column}': {lines_with_text}")
    if lines_with_text > 0:
        print(f"  Average words per line (with text): {average_words:.2f}")
        print(f"  Maximum words in a single line: {max_words}")
        print(
            f"  Minimum words in a single line (with text): {word_counts[word_counts > 0].min()}"
        )
    else:
        print("  No lines contained text for word count analysis.")


def main():
    """
    Main function to parse arguments and run the chosen analysis (n-grams or stats).
    """
    script_path = os.path.relpath(__file__)  # Get relative path for examples

    parser = argparse.ArgumentParser(
        description="Analyze text data from a CSV file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Available commands"
    )
    parser_ngrams = subparsers.add_parser(
        "ngrams",
        help="Analyze the most common n-grams.",
        description="Find and count the most frequent n-grams in a text column.",
        epilog=f"""
Examples:
  uv run {script_path} ngrams -i data.csv -c text_column -n 2
  uv run {script_path} ngrams -i data.csv -c text_column -n 3 -l 50 -o trigram_mapping.json
""",
    )
    parser_ngrams.add_argument(
        "-i", "--input-file", required=True, help="Path to the input CSV file."
    )
    parser_ngrams.add_argument(
        "-c",
        "--text-column",
        default="asts",
        help="Name of the column containing the text data (default: asts).",
    )
    parser_ngrams.add_argument(
        "-n",
        "--ngram-size",
        type=int,
        required=True,
        help="The size of the n-grams (e.g., 1 for unigrams, 2 for bigrams).",
    )
    parser_ngrams.add_argument(
        "-l",
        "--limit",
        type=int,
        default=10,
        help="Limit the output to the top N most common n-grams (default: 10).",
    )
    parser_ngrams.add_argument(
        "-o",
        "--output-mapping",
        help="Optional: Path to a JSON file to save the n-gram mapping.",
    )
    parser_ngrams.set_defaults(func=run_ngram_analysis)

    # --- Stats Subcommand Parser ---
    parser_stats = subparsers.add_parser(
        "stats",
        help="Calculate basic statistics for the text column.",
        description="Calculate average and maximum words per line in the text column.",
        epilog=f"""
Example:
  uv run {script_path} stats -i data.csv -c text_column
""",
    )
    parser_stats.add_argument(
        "-i", "--input-file", required=True, help="Path to the input CSV file."
    )
    parser_stats.add_argument(
        "-c",
        "--text-column",
        default="asts",  # Keep default or adjust as needed
        help="Name of the column containing the text data (default: asts).",
    )
    parser_stats.set_defaults(func=run_stats_analysis)

    args = parser.parse_args()

    if args.command == "ngrams" and args.ngram_size <= 0:
        print("Error: N-gram size must be a positive integer.", file=sys.stderr)
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
