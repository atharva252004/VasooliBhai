import pandas as pd

def check_payment_made(csv_file_path):
    # read csv file
    df = pd.read_csv(csv_file_path)
    
    # check if 'Payment Made Date' column exists in the dataframe
    if 'Payment Made Date' in df.columns:
        # check if there are any non-null values in the 'Payment Made Date' column
        if df['Payment Made Date'].notnull().any():
            return 1
        else:
            return 0
    else:
        return "Error: 'Payment Made Date' column not found in the csv file"
