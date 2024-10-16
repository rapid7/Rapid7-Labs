import argparse
import re
import os


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Process a file and decrypt specific patterns.\n\n"
                    "Example usage:\n"
                    "  python script.py --file /path/to/input/file --funcname decryption_function_name",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", required=True, help="Path to the input file")
    parser.add_argument(
        "-n", "--funcname", metavar='FUNC_NAME', type=str, required=True,
        help="Name of the decryption function to look for"
    )
    parser.add_argument(
        "-o", "--output", metavar='OUTPUT_PATH', type=str,
        help="Path to save the output file. If not provided, the output will be saved as 'out.au3' in the same directory as the input file"
    )
    return parser.parse_args()


def read_file(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Error: File '{file_path}' not found.")

    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()


def extract_values(file_content):
    """Extract XOR values, variable names, and separator using regex patterns."""
    pattern_xor_values = r"=\s*(\d+)\s*\$"  # Pattern to match values after '=' and before '$'
    pattern_var_names = r"\$(.*?)\s*="  # Pattern to match variable names between '$' and '='
    pattern_separator = r"\"(.*?)\""  # Pattern to match values inside double quotes

    xor_matches = re.findall(pattern_xor_values, file_content)
    var_name_matches = re.findall(pattern_var_names, file_content)
    separator_matches = re.findall(pattern_separator, file_content)

    if len(xor_matches) < 3 or len(var_name_matches) < 4 or len(separator_matches) < 1:
        raise ValueError("Error: Could not find enough matches for XOR values, variable names, or separator.")

    xor_params_array = xor_matches[:3]
    var_names_array = var_name_matches[:4]
    separator = separator_matches[0]

    return xor_params_array, var_names_array, separator


def decrypt_string(input_str, xor1, xor2, xor3, separator):
    """Decrypt the input string using XOR values and the separator."""
    decrypted = ""
    array1 = input_str.split(separator)

    for value in array1:
        try:
            int_value = int(value)
            xor_result = int_value ^ int(xor1)
            xor_result = xor_result ^ int(xor2)
            xor_result = xor_result ^ int(xor3)
            decrypted += chr(xor_result)
        except ValueError:
            print(f"Warning: '{value}' is not a valid integer and will be skipped.")
            continue

    return decrypted


def process_file_content(file_content, fname, xor_params_array, separator):
    """Find and decrypt function calls within the file content."""
    search_pattern = f'{fname}("'
    modified_content = []
    current_index = 0

    while current_index < len(file_content):
        start_index = file_content.find(search_pattern, current_index)

        if start_index == -1:
            modified_content.append(file_content[current_index:])
            break

        modified_content.append(file_content[current_index:start_index])
        value_start_index = start_index + len(search_pattern)
        value_end_index = file_content.find('"', value_start_index)

        if value_end_index == -1:
            raise ValueError("Error: Could not find the closing quote after the decryption function call.")

        value_to_decrypt = file_content[value_start_index:value_end_index]
        decrypted = decrypt_string(value_to_decrypt, xor_params_array[0], xor_params_array[1], xor_params_array[2],
                                   separator)

        end_of_func_call_index = file_content.find(')', value_end_index)
        if end_of_func_call_index == -1:
            raise ValueError("Error: Could not find the closing parenthesis of the function call.")

        modified_content.append(f'"{decrypted}"')
        current_index = end_of_func_call_index + 1

    return ''.join(modified_content)


def write_to_file(content, output_file_path):
    """Write the final modified content to the specified output file."""
    with open(output_file_path, 'w', encoding='utf-8') as file:
        file.write(content)


def main():
    args = parse_arguments()
    file_path = args.file
    fname = args.funcname
    output_file_path = args.output if args.output else os.path.join(os.path.dirname(file_path), "out.au3")

    try:
        file_content = read_file(file_path)
        xor_params_array, var_names_array, separator = extract_values(file_content)
        print(f"XOR Parameters: {xor_params_array}")
        print(f"Variable Names: {var_names_array}")
        print(f"Separator: {separator}")

        final_content = process_file_content(file_content, fname, xor_params_array, separator)
        write_to_file(final_content, output_file_path)

        print(f"File processed successfully. Output saved to '{output_file_path}'.")

    except (FileNotFoundError, ValueError) as e:
        print(str(e))


if __name__ == "__main__":
    main()
