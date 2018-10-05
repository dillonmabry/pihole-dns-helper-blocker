## PiHole/ThreatCrowd Project
Project to integrate DNS domains from PiHole into ThreatCrowd by performing relationship checks between domains
Utilize ThreatCrowd API by running near-real time communication between PiHole and a temporary staging database in order to update Regex rules, save known IPs of listed threats, as well as analysis for known malware/threats

### TODO:
- [X]  Integrate file hashes from known threats to be saved as staging data
- [X]  Integrate geolocation for origin lookup
- [ ]  Create view to perform malware analysis of known threats
- [ ]  Expand capabilities of PiHole by using a FaaS type infrastructure to asynchronously process DNS hits and check whether it is a known threat
- [ ]  Continue metadata analysis of malware and statistics, possibly in future develop algorithms to detect DNS lookups and process on the fly

## Analysis and Quick Models


```python
# Analyze and run simple models on data from malicious/non-malicious domains, ips, and their respective geolocations
# Data provided from regular internet usage and DNS lookups via PiHole

# Imports
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, LabelBinarizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score, confusion_matrix, auc, roc_curve
import matplotlib.pyplot as plt
from mpl_toolkits.basemap import Basemap
```


```python
# Malicious/Non-malicious ip geolocations
mal_df = pd.read_csv('/Users/dillonmabry/Desktop/Projects/PiHoleMetadata/Malicious/ipgeos.csv')
safe_df = pd.read_csv('/Users/dillonmabry/Desktop/Projects/PiHoleMetadata/Safe/ipgeos.csv')

# Setup malicious and safe original datasets
mal_df.insert(len(mal_df.columns), "Malicious", 1)
safe_df.insert(len(safe_df.columns), "Malicious", 0)

# Merge datasets with malicious indicators
df = pd.concat([mal_df, safe_df]).drop(["id"], axis=1)

# Shuffle final frame of original merged datasets safe/malicious
df = df.sample(frac=1)
```


```python
# Preserve original dataset
df_sk = df.copy()

# Clean dataset
df_sk = df_sk[(df_sk.ip_address != '127.0.0.1') & (df_sk.ip_address != 'localhost')] # remove local ips
df_sk = df_sk[df_sk.longitude != -9999] # remove outlier data
df_sk = df_sk[df_sk.latitude != -9999] # remove outlier data
df_sk = df_sk[df_sk.country_code != "N/P"] # remove not-provided
df_sk = df_sk[df_sk.continent_code != "N/P"] # remove not-provided
df_sk = df_sk.drop(["continent_code"], axis=1)
df_sk = df_sk.dropna() # drop N/A records
```


```python
agg = df_sk[df_sk.Malicious == 1].groupby(['country_code'])["country_code"].count().sort_values(ascending=False).iloc[0:10]

# Top malicious ipgeolocations by country
ax = agg.plot(kind='bar', title ="Malicious Countries Grouped", figsize=(10, 5), legend=True, fontsize=12)
ax.set_xlabel("Country", fontsize=12)
ax.set_ylabel("Count", fontsize=12)
plt.show()
```


![png](https://user-images.githubusercontent.com/10522556/46509913-a43a0600-c813-11e8-93d5-de4f814f2dca.png)



```python
isp_agg = df_sk[df_sk.Malicious == 1].groupby(['country_code', 'isp'])["country_code"].count().sort_values(ascending=False).iloc[0:10]

# Top malicious isps by country
ax = isp_agg.plot(kind='bar', title ="Malicious ISPs Grouped by Country", figsize=(10, 5), legend=True, fontsize=12)
ax.set_xlabel("Country, ISP", fontsize=12)
ax.set_ylabel("Count", fontsize=12)
plt.show()
```


![png](https://user-images.githubusercontent.com/10522556/46509914-a43a0600-c813-11e8-8dfc-1666ab3bcd7c.png)



```python
mal_lngs = df_sk[df_sk.Malicious == 1]["longitude"].values
mal_lats = df_sk[df_sk.Malicious == 1]["latitude"].values

lngs = df_sk[df_sk.Malicious == 0]["longitude"].values
lats = df_sk[df_sk.Malicious == 0]["latitude"].values

plt.figure(figsize=(14, 8))
earth = Basemap()
earth.bluemarble(alpha=0.75)
plt.scatter(mal_lngs, mal_lats, c='red',alpha=0.5, zorder=10)
plt.scatter(lngs, lats, c='blue',alpha=0.5, zorder=5)
plt.xlabel("IP Geolocations - Malicious (Red), Non-Malicious (Blue)")
plt.show()
```



![png](https://user-images.githubusercontent.com/10522556/46509915-a43a0600-c813-11e8-8c63-2b2a19bf9b3c.png)



```python
# Numeric Categorical encoding and feature extraction/cleanup
le = LabelEncoder()
# Categorical attrs
le.fit(df_sk["country_code"])
df_sk["country_code"] = le.transform(df_sk["country_code"])
le.fit(df_sk["isp"])
df_sk["isp"] = le.transform(df_sk["isp"])
le.fit(df_sk["parent_domain"])
df_sk["parent_domain"] = le.transform(df_sk["parent_domain"])

# Drop unnecessary attributes
df_sk = df_sk.drop(["ip_address"], axis=1) # IP is too numerous/sparse, need to find a regularization pattern for subnets
```


```python
# Convert to np arrays
labels = df_sk["Malicious"].values
label_names = ["Malicious", "Safe"]
df_sk = df_sk.drop(["Malicious"], axis=1) # DROP MALICIOUS/NON IDENTIFIER OF MAIN MERGED DATASET BEFORE MODELING
features = df_sk.values
feature_names = df_sk.columns[0:]
```


```python
# Split our data
train, test, train_labels, test_labels = train_test_split(features,
                                                          labels,
                                                          test_size=0.33,
                                                          random_state=42)
```


```python
# Logistic Regression
lr = LogisticRegression(random_state=0)
lr.fit(train, train_labels)
preds = lr.predict(test)
print(accuracy_score(test_labels, preds))
```

    0.929078014184



```python
# Random Forest
rf = RandomForestClassifier(n_estimators=100, max_depth=2, random_state=0)
rf.fit(train, train_labels)
preds = rf.predict(test)
print(accuracy_score(test_labels, preds))
print(df_sk.columns)
print(rf.feature_importances_)
```

    0.962269503546
    Index(['parent_domain', 'country_code', 'latitude', 'longitude', 'isp'], dtype='object')
    [ 0.73240397  0.07076328  0.02346796  0.0510711   0.12229368]



```python
# Gaussian
gnb = GaussianNB()
model = gnb.fit(train, train_labels)
preds = gnb.predict(test)
print(accuracy_score(test_labels, preds))
```

    0.915602836879



```python
# Decision Classifier
dclf = DecisionTreeClassifier(random_state=0)
dclf.fit(train, train_labels)
preds = dclf.predict(test)
print(accuracy_score(test_labels, preds))
cross_val_score(dclf, test, test_labels, cv=10)
print(dclf.feature_importances_)
```

    0.996312056738
    [  9.69256958e-01   2.77148766e-04   3.02767067e-03   6.19121418e-03
       2.12470083e-02]



```python
def show_roc(model, test, test_labels):
    # Predict
    probs = model.predict_proba(test)
    preds = probs[:,1]
    fpr, tpr, threshold = roc_curve(test_labels, preds)
    roc_auc = auc(fpr, tpr)
    # Chart
    plt.title('Receiver Operating Characteristic')
    plt.plot(fpr, tpr, 'b', label = 'AUC = %0.2f' % roc_auc)
    plt.legend(loc = 'lower right')
    plt.plot([0, 1], [0, 1],'r--')
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.ylabel('True Positive Rate')
    plt.xlabel('False Positive Rate')
    plt.show()
```


```python
# LR ROC
show_roc(lr, test, test_labels) # Overfitting
```


![png](https://user-images.githubusercontent.com/10522556/46509916-a43a0600-c813-11e8-8941-f2ed799ae932.png)



```python
# RF ROC
show_roc(rf, test, test_labels) # Overfitting
```


![png](https://user-images.githubusercontent.com/10522556/46509917-a43a0600-c813-11e8-8783-9d341046c4a0.png)



```python
# GB ROC
show_roc(gnb, test, test_labels) # Appropriate ROC
```


![png](https://user-images.githubusercontent.com/10522556/46509919-a43a0600-c813-11e8-8dda-4610de88079c.png)



```python
show_roc(dclf, test, test_labels) # Overfitting example
```


![png](https://user-images.githubusercontent.com/10522556/46509920-a43a0600-c813-11e8-9c0f-c20805169aea.png)



```python
# TODO Perform second test with secondary test set with new data
# Add more features and examine overfitting
```

