from datetime import datetime
from clickhouse_client import client

def save_to_clickhouse(input_text, prediction):
    client.insert(
        'mydb.predictions',
        [
            [datetime.now(), input_text, float(prediction)]
        ],
        column_names=['timestamp', 'input', 'prediction']
    )