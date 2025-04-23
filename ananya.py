pip install pandas scikit-learn mysql-connector-python
import mysql.connector
import pandas as pd
from sklearn.cluster import DBSCAN

def detect_and_blacklist_ip(ip_address):
    # DB connection
    conn = mysql.connector.connect(
       host=os.getenv("DB_HOST"),
       user=os.getenv("DB_USER"),
       password=os.getenv("DB_PASSWORD"),
       database=os.getenv("DB_NAME")
    )
    cursor = conn.cursor(dictionary=True)

    # Fetch last 10 transactions for the given IP
    query = """
        SELECT amount, time
        FROM transaction_table
        WHERE ip_address = %s
        ORDER BY time DESC
        LIMIT 10
    """
    cursor.execute(query, (ip_address,))
    transactions = pd.DataFrame(cursor.fetchall())

    if transactions.empty:
        print("No transactions found for this IP.")
        return

    # Apply DBSCAN to detect outliers
    X = transactions['amount'].values.reshape(-1, 1)
    db = DBSCAN(eps=1.5, min_samples=2).fit(X)
    transactions['cluster'] = db.labels_

    spikes = transactions[transactions['cluster'] == -1]

    if not spikes.empty:
        # Check if already blacklisted
        cursor.execute("SELECT 1 FROM blacklisted_ip WHERE ip_address = %s", (ip_address,))
        if cursor.fetchone():
            print(f"IP {ip_address} already blacklisted.")
        else:
            insert_query = """
                INSERT INTO blacklisted_ip (ip_address, reason)
                VALUES (%s, %s)
            """
            reason = "Spike in transaction amount"
            cursor.execute(insert_query, (ip_address, reason))
            conn.commit()
            print(f"IP {ip_address} blacklisted due to spike(s).")
    else:
        print("No spikes detected.")

    cursor.close()
    conn.close()