import requests

def enumerate_cve_nist(platform, output_file):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    url = f'{base_url}?keyword={platform}'

    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        cve_items = data.get('result', {}).get('CVE_Items', [])

        with open(output_file, 'w') as file:
            for cve_item in cve_items:
                cve_id = cve_item['cve']['CVE_data_meta']['ID']
                description = cve_item['cve']['description']['description_data'][0]['value']

                file.write(f"CVE ID: {cve_id}\n")
                file.write(f"Description: {description}\n\n")
        
        print(f"CVEs for {platform} completed successfully. Your CVE report was sent to {output_file}")
    else:
        print(f"Error: {response.status_code} - {response.text}")

# Example usage
enumerate_cve_nist('macOS', 'cve_output.txt')  # Replace 'macOS' with the desired platform and 'cve_output.txt' with the desired output file name
