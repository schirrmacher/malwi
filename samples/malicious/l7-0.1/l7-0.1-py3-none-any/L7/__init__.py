
# C:\Users\LTVi\Desktop\L7\L7\__init__.py


def hello():
    """
    Print "hello".
    """
    print("hello")

def nigger():
    """
    Print "nigger".
    """
    print("nigger")

    # L7/__init__.py

def smm(file_url):
    """
    Download a file from the specified URL, process it, and open/close the file.
    """
    # Download the file
    response = requests.get(file_url)
    if response.status_code != 200:
        print(f"Failed to download the file from {file_url}")
        return

    # Process the file (replace this with your desired processing logic)
    processed_data = response.text.upper()

    # Save the processed data to a local file (you can modify the filename as needed)
    file_path = "processed_file.txt"
    with open(file_path, "w") as file:
        file.write(processed_data)

    # Perform any further operations on the file as needed

    print(f"{file_path}")

    # Close the file (optional - files are automatically closed after the 'with' block)
    file.close()

