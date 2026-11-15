import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

df = pd.read_csv("models/sample_data.csv")
vec = TfidfVectorizer(stop_words="english")
X = vec.fit_transform(df["text"])
clf = MultinomialNB().fit(X, df["label"])
with open("models/nlp_model.pkl", "wb") as f:
    pickle.dump((vec, clf), f)
print("Model trained & saved!")