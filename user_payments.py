import pandas as pd

def count_positive_differences(csv_file_path):
    # Read the CSV file into a DataFrame
    data = pd.read_csv(csv_file_path)

    # Convert date strings to datetime objects
    data['due_date'] = pd.to_datetime(data['due_date'], format='%d-%m-%Y')
    data['payment_date'] = pd.to_datetime(data['payment_date'], format='%d-%m-%Y')

    # Calculate the differences between due_date and payment_date
    data['date_difference'] = data['payment_date'] - data['due_date']

    # Count the number of positive differences
    positive_difference_count = (data['date_difference'] > pd.Timedelta(0)).sum()

    return positive_difference_count


def good_bad(username):
    late_payments_count = count_positive_differences('user_data/' + username + '.csv')

    if late_payments_count > 0:
        return False

    return True

def get_column_as_list(username, column_name):
    try:
        # Read the CSV file into a DataFrame
        data = pd.read_csv('user_data/' + username + '.csv')

        # Check if the specified column exists in the DataFrame
        if column_name in data.columns:
            column_values = data[column_name].tolist()
            return column_values
        else:
            return None  # Return None if the column doesn't exist

    except Exception as e:
        print(f"An error occurred: {e}")
        return None


