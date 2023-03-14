import requests
from requests.structures import CaseInsensitiveDict
import re

# API url
url = "https://api.openai.com/v1/completions"

# API header required to work
headers = CaseInsensitiveDict()
headers["Content-Type"] = "application/json"
headers["Authorization"] = "Bearer TOKEN" # Replace 'TOKEN' with your openapi token

# Quick Info:
#    model: the type of model you want to use
#    prompt: the question you want to ask
#    temperature: the randomness of the output (higher is more random)
#    max_tokens: the amount of token for both the question and answer

# Read each vulnerability in the input_file variable
with open('./input/vulns.txt', 'r') as file:
  for vuln in file:
    # Remove trailing whitespace and newlines from the vuln string
    vuln = vuln.strip()

    # Use the .format() method to insert vuln into the data_description string
    data_description = """
        {{
          "model": "text-davinci-003",
          "prompt": "Write a description for {}.",
          "temperature": 1,
          "max_tokens": 30,
          "top_p": 1,
          "frequency_penalty": 0,
          "presence_penalty": 0
        }}
        """.format(vuln)

    # Grab a remediation for the vulnerability
    data_remediation = """
        {{
          "model": "text-davinci-003",
          "prompt": "Write a remediation for {}.",
          "temperature": 1,
          "max_tokens": 30,
          "top_p": 1,
          "frequency_penalty": 0,
          "presence_penalty": 0
        }}
        """.format(vuln)

    resp_desc = requests.post(url, headers=headers, data=data_description)

    resp_rem = requests.post(url, headers=headers, data=data_remediation)

    print(resp_desc.text, resp_rem.text)

    with open('./output/output_raw.txt', 'a') as f:
      f.write(resp_desc.content.decode('utf-8'))
      f.write(resp_rem.content.decode('utf-8'))

# Grep the Descriptions from the output_raw.txt
# Open the input and output files
with open('./output/output_raw.txt', 'r') as input_file, open('./output/output_refined.txt', 'a') as output_file:
    # Iterate over the lines of the input file
    for line in input_file:
        # Define a regular expression to match the "text" parameter
        pattern = r'"text":\s*"([^"]+)"'

        # Extract the "text" parameter from the line
        match = re.search(pattern, line)
        if match:
            filtered_data = match.group(1)

            # Filter out the contents of the "text" parameter
            filtered_description = re.sub(r'[^a-zA-Z0-9\s]', '', filtered_data)

            # Remove the first two letters of the filtered description
            filtered_description = filtered_description[2:]

            # Write the filtered description to the output file
            output_file.write(filtered_description + '\n')
        else:
            print('No match found')
