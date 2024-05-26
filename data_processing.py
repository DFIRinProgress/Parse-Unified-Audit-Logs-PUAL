import json
import pandas as pd

class DataProcessor:
    def parse_and_filter(self, filepath, ip_list):
        df = pd.read_csv(filepath)
        if 'AuditData' not in df.columns:
            raise ValueError("The selected file does not contain an 'AuditData' column.")

        # Parse the JSON data in 'AuditData' column
        audit_data_list = [json.loads(item) for item in df['AuditData']]

        # Create a new DataFrame from the parsed audit data
        parsed_df = pd.DataFrame(audit_data_list)

        # Filter the DataFrame based on the IP list
        if ip_list:
            parsed_df = parsed_df[parsed_df['ClientIP'].isin(ip_list)]

        return parsed_df
