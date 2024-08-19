import pandas as pd

# Correct file path to include the CSV file name
file_path = '/Users/bunkheangheng/Desktop/projectPhish/data/Phishing_Email_2.csv'

# Load the dataset
df = pd.read_csv(file_path)

# Display basic information about the dataset
print("Dataset Info:")
print(df.info())

# Display the first few rows of the dataset
print("\nFirst 5 Rows:")
print(df.head())

# Check the distribution of 'Email Type'
print("\nEmail Type Distribution:")
print(df['Email Type'].value_counts())
