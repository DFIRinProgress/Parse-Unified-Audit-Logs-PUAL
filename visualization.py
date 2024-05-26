import pandas as pd
import matplotlib.pyplot as plt

class Visualization:
    def create_visualizations(self, df):
        visualizations = []

        # Operation frequency bar chart
        fig1, ax1 = plt.subplots(figsize=(10, 6))
        operation_counts = df['Operation'].value_counts()
        operation_counts.plot(kind='bar', ax=ax1)
        ax1.set_title("Operation Frequency")
        ax1.set_xlabel("Operation")
        ax1.set_ylabel("Count")
        fig1.tight_layout()  # Adjust layout to ensure everything fits
        visualizations.append(fig1)

        # IP address pie chart
        fig2, ax2 = plt.subplots(figsize=(10, 6))
        ip_counts = df['ClientIP'].value_counts()
        ip_counts.plot(kind='pie', ax=ax2, autopct='%1.1f%%')
        ax2.set_title("Client IP Distribution")
        ax2.set_ylabel("")
        fig2.tight_layout()  # Adjust layout to ensure everything fits
        visualizations.append(fig2)

        # Operation timeline line plot
        fig3, ax3 = plt.subplots(figsize=(10, 6))
        df['CreationTime'] = pd.to_datetime(df['CreationTime'])
        timeline = df.set_index('CreationTime').resample('D').size()
        timeline.plot(kind='line', ax=ax3)
        ax3.set_title("Operation Timeline")
        ax3.set_xlabel("Time")
        ax3.set_ylabel("Number of Operations")
        fig3.tight_layout()  # Adjust layout to ensure everything fits
        visualizations.append(fig3)

        return visualizations
