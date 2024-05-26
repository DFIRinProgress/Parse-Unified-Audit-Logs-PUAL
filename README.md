# Parse Unified Audit Logs (PUAL)

This tool is designed to support the investigation of Unified Audit Logs. The tool processes the logs, enriches IP addresses,  offers filtering and provides visualizations. Happy Hunting!

[GPT assisted coding]

## Features
- **Data Processing**: Expands JSON from audit data for analysis.
- **IP Enrichment**: Provides additional context for IP addresses using IPinfo.
- **Filtering:** Allows for filtering based on a keyword, IP address and operation. 
- **Visualization**: Generates charts and plots for visualization of trends and patterns.
- **Export**: Exports parsed and filtered audit data to a CSV file.

## Preview


## Installation

To install the required dependencies, execute the following command:
```
pip install -r requirements.txt
```
**Note**: The Microsoft Visual C++ Redistributable is required for this tool.

## Usage
### Running the Tool 
1. In the config.json file replace "YOUR_TOKEN_HERE" with your IPinfo token. 
2. Start the application by executing the main script:
```
python .\main.py
```
#### File Selection
- **Select CSV File**: Select the Unified Audit Log in CSV format. The selected file will be processed and displayed in the application.
  
#### Dashboard Overview
- **Total Events**: Displays the total number of events.
- **Unique IP Addresses**: Shows the count of unique IP addresses.
- **Most Frequent Operations**: Lists the most frequent operations in the log.
  
#### Search and Filter
- **Filter by Operation**: Use the dropdown menu to filter the audit log by specific operations.
- **Search**: Enter keywords to search through the logs.

#### Visualizations
- **Operation Frequency Bar Chart**: Displays the frequency of different operations.
- **Client IP Distribution Pie Chart**: Shows the distribution of IP addresses.
- **Operation Timeline Line Plot**: Illustrates the number of operations over time.

## Example Usage
1. **Upload a Unified audit log file**: Use the "Select CSV File" button to select your audit log.
2. **Parse and Filter**: Use the parse and filter button to process the selected file expanding the JSON data. 
3. **Enrich IP addresses**: Use the IP enrichment feature to get additional context using IPinfo.
4. **Filtering and Searching**: Use the search and filter options to narrow down on a specific operation, keyword or IP addresses.
5. **Visualizations**: Visualize charts and plots to identify trends and patterns.

## Contributing

If you have any suggestions for improvements or new features, please create an issue or submit a pull request. 

