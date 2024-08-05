import pandas as pd
import spacy
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Input
from sklearn.preprocessing import LabelEncoder, MultiLabelBinarizer
from sklearn.model_selection import train_test_split


nlp = spacy.load("en_core_web_sm")


try:
    rawdt1 = pd.read_csv('cve.csv', encoding='latin1', low_memory=False)
    rawdt2 = pd.read_csv('products.csv', encoding='latin1', low_memory=False)
    rawdt3 = pd.read_csv('vendor_product.csv', encoding='latin1', low_memory=False)
    rawdt4 = pd.read_csv('vendors.csv', encoding='latin1', low_memory=False)
except UnicodeDecodeError:
    rawdt1 = pd.read_csv('cve.csv', encoding='latin1', low_memory=False)
    rawdt2 = pd.read_csv('products.csv', encoding='latin1', low_memory=False)
    rawdt3 = pd.read_csv('vendor_product.csv', encoding='latin1', low_memory=False)
    rawdt4 = pd.read_csv('vendors.csv', encoding='latin1', low_memory=False)

data = pd.DataFrame({
    'cve_id': rawdt1["CV"].head(1000),
    'date_published': rawdt1["pub_date"].head(1000),
    'cvss': rawdt1["cvss"].head(1000),
    'cwe_name': rawdt1["cwe_name"].head(1000),
    'vulnerable_product': rawdt2["vulnerable_product"].head(1000),
    'vendor': rawdt4["vendor"].head(1000),
    'summary': rawdt1["summary"].head(1000)
})


label_encoder_cwe = LabelEncoder()
label_encoder_vul_product = LabelEncoder()
label_encoder_vendor = LabelEncoder()

data['cwe_name'] = label_encoder_cwe.fit_transform(data['cwe_name'])
data['vulnerable_product'] = label_encoder_vul_product.fit_transform(data['vulnerable_product'])
data['vendor'] = label_encoder_vendor.fit_transform(data['vendor'])


features_df = data[['cvss', 'cwe_name', 'vulnerable_product', 'vendor']]
summaries = data['summary']
target = data['cwe_name']


tokenized_summaries = [nlp(summary).vector for summary in summaries]


X_train, X_test, y_train, y_test = train_test_split(tokenized_summaries, target, test_size=0.2, random_state=42)

X_train_tensor = tf.convert_to_tensor(X_train)
X_test_tensor = tf.convert_to_tensor(X_test)


feature_extractor = Sequential([
    Input(shape=(96,)),
    Dense(256, activation='relu'),
    Dense(128, activation='relu')
])


feature_extractor.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])


feature_extractor.fit(X_train_tensor, y_train, epochs=50, batch_size=5, validation_split=0.1)


vulnerability_predictor = Sequential([
    Input(shape=(128,)),
    Dense(128, activation='relu'),
    Dense(64, activation='relu'),
    Dense(len(label_encoder_cwe.classes_), activation='sigmoid')
])


vulnerability_predictor.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

X_train_features = feature_extractor.predict(X_train_tensor)
X_test_features = feature_extractor.predict(X_test_tensor)


mlb = MultiLabelBinarizer(classes=label_encoder_cwe.classes_)
y_train_bin = mlb.fit_transform([[i] for i in y_train])
y_test_bin = mlb.transform([[i] for i in y_test])


vulnerability_predictor.fit(X_train_features, y_train_bin, epochs=50, batch_size=5, validation_split=0.1)


def extract_features_from_iac(iac_code):
    doc = nlp(iac_code)
    return doc.vector


def get_vulnerability_details(cwe_code):
    row = data[data['cwe_name'] == cwe_code].iloc[0]
    return {
        'cve_id': row['cve_id'],
        'cvss': row['cvss'],
        'cwe_name': label_encoder_cwe.inverse_transform([row['cwe_name']])[0],
        'vulnerable_product': label_encoder_vul_product.inverse_transform([row['vulnerable_product']])[0],
        'vendor': label_encoder_vendor.inverse_transform([row['vendor']])[0],
        'summary': row['summary']
    }


def predict_vulnerabilities(iac_code):
    features = extract_features_from_iac(iac_code)
    features = feature_extractor.predict(tf.convert_to_tensor([features]))
    prediction = vulnerability_predictor.predict(features)


    top_k_indices = prediction[0].argsort()[-5:][::-1]  # Get indices of top 5 vulnerabilities
    vulnerabilities = [get_vulnerability_details(idx) for idx in top_k_indices]
    return vulnerabilities


