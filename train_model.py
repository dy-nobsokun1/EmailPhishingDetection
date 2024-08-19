import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.metrics.pairwise import cosine_similarity
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from imblearn.over_sampling import RandomOverSampler
import nltk
import numpy as np
import joblib
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Download necessary NLTK resources
nltk.download('stopwords')
nltk.download('punkt')

# Load dataset
df = pd.read_csv('/Users/bunkheangheng/Desktop/projectPhish/data/Phishing_Email_2.csv')

# Fill missing email text with an empty string
df['Email Text'] = df['Email Text'].fillna('')

# Define preprocessing function
def preprocess_text(text):
    words = word_tokenize(text)
    stop_words = set(stopwords.words('english'))
    words = [word for word in words if word.lower() not in stop_words]
    return ' '.join(words)

# Apply preprocessing
df['Processed Text'] = df['Email Text'].apply(preprocess_text)

# Separate features and labels
X = df['Processed Text']
y = df['Email Type']

# Balance dataset using RandomOverSampler
ros = RandomOverSampler(random_state=42)
X_res, y_res = ros.fit_resample(X.values.reshape(-1, 1), y)

# Split into training and testing datasets
X_train, X_test, y_train, y_test = train_test_split(X_res.ravel(), y_res, test_size=0.2, random_state=42)

# Build a TF-IDF vectorizer
tfidf_vectorizer = TfidfVectorizer(max_features=20000, ngram_range=(1, 3))

# Fit and transform the training data
X_train_tfidf = tfidf_vectorizer.fit_transform(X_train)
X_test_tfidf = tfidf_vectorizer.transform(X_test)

# Train a RandomForest Classifier
rf_classifier = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42)
rf_classifier.fit(X_train_tfidf, y_train)

# Save the trained model and vectorizer
joblib.dump((tfidf_vectorizer, rf_classifier), 'model/similarity_email_classifier.pkl')

# Define a function to calculate the similarity score
def calculate_similarity(email_text, tfidf_vectorizer, rf_classifier, X_train_tfidf):
    """
    Calculate the similarity between the input email text and the phishing emails in the training set.
    """
    processed_text = preprocess_text(email_text)
    email_tfidf = tfidf_vectorizer.transform([processed_text])

    # Compute cosine similarity between input email and all phishing emails in the training set
    similarities = cosine_similarity(email_tfidf, X_train_tfidf)
    
    # Get the maximum similarity score
    max_similarity = np.max(similarities)

    # Calculate the phishing probability based on the maximum similarity
    phishing_probability = round(max_similarity * 100, 2)

    return phishing_probability

# Example usage
phishing_example = df[df['Email Type'] == 'Phishing Email'].iloc[0]['Email Text']
phishing_probability = calculate_similarity(phishing_example, tfidf_vectorizer, rf_classifier, X_train_tfidf)
print(f"Phishing Probability for Known Example: {phishing_probability}%")
