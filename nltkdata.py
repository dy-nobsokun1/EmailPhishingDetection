import nltk

# Define the path to store NLTK data
nltk_data_path = '/Users/bunkheangheng/Desktop/projectPhish/data'

# Ensure the directory exists
import os
if not os.path.exists(nltk_data_path):
    os.makedirs(nltk_data_path)

# Add the path to the NLTK data search path
nltk.data.path.append(nltk_data_path)

# Try downloading stopwords and punkt tokenizer
nltk.download('stopwords', download_dir=nltk_data_path)
nltk.download('punkt', download_dir=nltk_data_path)

# Test NLTK functionality
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

text = "This is a test sentence for stopword removal."

# Tokenization and stopword removal
tokens = word_tokenize(text)
filtered_words = [word for word in tokens if word.lower() not in stopwords.words('english')]

print("Filtered words:", filtered_words)
