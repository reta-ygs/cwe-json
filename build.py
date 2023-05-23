import os
import requests
import zipfile
import xmltodict
import json

# Create directories if they don't exist
if not os.path.exists('build'):
    os.makedirs('build')

if not os.path.exists('public'):
    os.makedirs('public')

# Step 1: Download the ZIP file with headers
zip_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# Check if cache headers file exists
cache_headers_file = 'cache-headers.txt'
if os.path.exists(cache_headers_file):
    # Read cache headers from file
    with open(cache_headers_file, 'r') as headers_file:
        headers = headers_file.read().splitlines()
        etag_header = headers[0]
        last_modified_header = headers[1]

    # Send conditional request with ETag and Last-Modified headers
    response = requests.get(zip_url, headers={'If-None-Match': etag_header, 'If-Modified-Since': last_modified_header})

    # Check if server responds with 304 Not Modified
    if response.status_code == 304:
        print("No changes since the last download.")
        exit()
else:
    response = requests.get(zip_url)

# Check if ZIP file needs to be saved
if response.status_code == 200:
    # Save the ZIP file
    with open('build/cwec_latest.xml.zip', 'wb') as zip_file:
        zip_file.write(response.content)

    # Save cache headers to file
    etag_header = response.headers.get('ETag', '')
    last_modified_header = response.headers.get('Last-Modified', '')

    with open(cache_headers_file, 'w') as headers_file:
        headers_file.write(f"{etag_header}\n{last_modified_header}")
else:
    print("Failed to download the ZIP file.")
    exit()

# Extract the XML file
with zipfile.ZipFile('build/cwec_latest.xml.zip', 'r') as zip_ref:
    zip_ref.extractall('build')

# Find the extracted XML file
extracted_files = os.listdir('build')
xml_file_path = None

for file_name in extracted_files:
    if file_name.endswith('.xml'):
        xml_file_path = os.path.join('build', file_name)
        break

# Check if XML file found
if xml_file_path is None:
    print("No XML file found in the extracted files.")
    exit()

# Step 4: Convert XML to JSON and write as separate files
with open(xml_file_path, 'r') as xml_file:
    data_dict = xmltodict.parse(xml_file.read())
    index_data = {}

    for entry in data_dict['Weakness_Catalog']['Weaknesses']['Weakness']:
        cwe_id = entry['@ID']
        name = entry['@Name']

        index_data[cwe_id] = name

        json_data = json.dumps(entry)

        json_file_path = f'public/{cwe_id}.json'

        with open(json_file_path, 'w') as json_file:
            json_file.write(json_data)

    # Write index.json
    index_json_file_path = 'public/index.json'
    with open(index_json_file_path, 'w') as index_json_file:
        index_json_file.write(json.dumps(index_data))
