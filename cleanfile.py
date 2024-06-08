import re

def delete_comment_lines(input_file, output_file):
    # Open the input file and read all lines
    with open(input_file, 'r') as file:
        lines = file.readlines()

    # Regular expression to match lines starting with "// "
    pattern = re.compile(r'^//\ ')

    # Filter out lines that match the pattern
    filtered_lines = [line for line in lines if not pattern.match(line)]

    # Write the filtered lines to the output file
    with open(output_file, 'w') as file:
        file.writelines(filtered_lines)

# Example usage
input_file = 'stage1.js'   # Replace with your input file name
output_file = 'stage2.js'  # Replace with your output file name, can be the same as input file to

delete_comment_lines(input_file, output_file)
