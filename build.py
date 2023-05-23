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

# Step 1: Download the ZIP file
zip_url = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
response = requests.get(zip_url)

# Step 2: Save the ZIP file
zip_file_path = 'build/cwec_latest.xml.zip'
with open(zip_file_path, 'wb') as zip_file:
    zip_file.write(response.content)

# Step 3: Extract the XML file
with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
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

    for entry in data_dict['Weakness_Catalog']['Weaknesses']['Weakness']:
        entry_id = entry['@ID']
        json_data = json.dumps(entry)

        json_file_path = f'public/{entry_id}.json'

        with open(json_file_path, 'w') as json_file:
            json_file.write(json_data)
