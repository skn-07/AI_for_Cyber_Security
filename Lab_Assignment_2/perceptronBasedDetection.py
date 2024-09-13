import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

filePath = 'Lab_Assignment_2/dataset/NSL_KDD_Train.csv'   # Path for the dataset

df = pd.read_csv(filePath, header = None)   # Loading the dataset to a dataframe using Pandas
print(df.head(10))  # Displaying the first few rows of the dataset

# df.info()

df = df.dropna() # Handling missing values by dropping them

# Encoding categorical features
le = LabelEncoder()
