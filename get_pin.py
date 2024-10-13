import sqlite3

def get_super_admin_pin(db_path):
    connection = sqlite3.connect(db_path)
    cursor = connection.cursor()
    cursor.execute("SELECT pin FROM User WHERE is_super_admin = 1")
    super_admin = cursor.fetchone()
    connection.close()
    
    if super_admin:
        return super_admin[0]
    else:
        return None

if __name__ == "__main__":
    db_path = 'instance/donation.db'  # Replace with your actual database path
    pin = get_super_admin_pin(db_path)
    if pin:
        print(f"The Super Admin PIN is: {pin}")
    else:
        print("No Super Admin found.")
