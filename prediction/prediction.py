import os
import time
import sys
import pandas as pd
import numpy as np
import joblib

# Set the relative path to the 'pickles' directory
pickle_directory = '/CICFlowMeter/prediction/pickles'

# Load the saved components
feature_columns = joblib.load(os.path.join(pickle_directory, 'feature_columns.pkl'))
medians = joblib.load(os.path.join(pickle_directory, 'medians.pkl'))
skewed_cols = joblib.load(os.path.join(pickle_directory, 'skewed_cols.pkl'))
scaler = joblib.load(os.path.join(pickle_directory, 'minmax_scaler.pkl'))
rf_binary = joblib.load(os.path.join(pickle_directory, 'rf_binary_model.pkl'))
rf_multi = joblib.load(os.path.join(pickle_directory, 'rf_multi_model.pkl'))
le = joblib.load(os.path.join(pickle_directory, 'label_encoder.pkl'))

def preprocess_new_data(new_df):
    # Handle missing (hyphens/spaces to NaN)
    new_df.replace(["-", " "], np.nan, inplace=True)
    
    # Select only the features used in training
    missing_cols = set(feature_columns) - set(new_df.columns)
    if missing_cols:
        raise ValueError(f"Missing required columns in new data: {missing_cols}")
    extra_cols = set(new_df.columns) - set(feature_columns)
    if extra_cols:
        print(f"Warning: Extra columns in new data will be dropped: {extra_cols}")
    new_df.drop(columns=extra_cols, inplace=True)
    new_df = new_df[feature_columns]  # Reorder to match training
    
    # Replace inf with nan
    new_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Fill NaNs with medians
    for col, med in medians.items():
        new_df[col] = new_df[col].fillna(med)
    
    # Clip extreme values
    new_df = new_df.clip(lower=-1e100, upper=1e100)
    
    # Log-transform skewed columns
    new_df[skewed_cols] = np.log1p(new_df[skewed_cols].clip(lower=0))
    
    # Normalize/Scale
    new_scaled = pd.DataFrame(scaler.transform(new_df), columns=new_df.columns)
    
    return new_scaled

def predict(X_new):
    # Binary prediction
    pred_binary = rf_binary.predict(X_new)
    
    # Initialize predictions as 'Normal'
    predictions = np.array(['Normal'] * len(pred_binary), dtype=object)
    
    # For predicted attacks, run multi-class
    mask_attack = (pred_binary == 1)
    if np.any(mask_attack):
        X_attack = X_new[mask_attack]
        pred_multi = rf_multi.predict(X_attack)
        predictions[mask_attack] = le.inverse_transform(pred_multi)
    
    return predictions

# Folder path to monitor
folder = '/tmp/captures'

# Ensure the folder exists
if not os.path.exists(folder):
    print(f"Folder {folder} does not exist. Creating it.")
    os.makedirs(folder)

print("Monitoring folder for CSV files... Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(10)  # Check every 10 seconds
        try:
            csv_files = [f for f in os.listdir(folder) if f.endswith('.csv')]
            for csv in csv_files:
                full_path = os.path.join(folder, csv)
                df_new = pd.read_csv(full_path)
                # Process all rows in the file
                preprocessed = preprocess_new_data(df_new)
                preds = predict(preprocessed.values)  # Convert to numpy if needed
                for i, pred in enumerate(preds):
                    print(f"Prediction for flow {i + 1} in {csv}: {pred}")
                # Delete the file after processing
                os.remove(full_path)
                print(f"Processed and deleted: {csv}")
        except Exception as e:
            print(f"Error reading/processing CSV: {e}")
except KeyboardInterrupt:
    print("Stopping monitoring...")

print("Monitoring stopped. Final predictions processed.")
