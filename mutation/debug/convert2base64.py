import base64
import sys

def convert_der_to_base64(der_file_path):
    """Read a DER file and encode its contents to Base64."""
    try:
        # Open the file in binary read mode
        with open(der_file_path, 'rb') as file:
            der_data = file.read()
        
        # Encode the binary data to Base64
        base64_encoded = base64.b64encode(der_data)
        
        # Convert bytes to string for display
        base64_string = base64_encoded.decode('utf-8')
        
        return base64_string
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_der_file>")
        sys.exit(1)

    # Get the file path from command line arguments
    file_path = sys.argv[1]

    # Convert the DER file to Base64 and print the result
    base64_output = convert_der_to_base64(file_path)
    print(base64_output)
