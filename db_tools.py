import mysql.connector
from datetime import datetime


def create_new_db(db, cursor):
    cursor.execute("CREATE DATABASE IF NOT EXISTS netpulse_db")

    cursor.execute("USE netpulse_db")

    create_device_table = """
    CREATE TABLE IF NOT EXISTS DEVICE (
        Device_id INT AUTO_INCREMENT PRIMARY KEY,
        Mac_address VARCHAR(45) NOT NULL UNIQUE,
        IP_address VARCHAR(45) NOT NULL,
        Firmware VARCHAR(45),
        CPU_usage DECIMAL(5,2)
    );
    """

    create_packet_table = """
    CREATE TABLE IF NOT EXISTS PACKET (
        Packet_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        Time_of_detection DOUBLE,
        Src_mac VARCHAR(45),
        Dst_mac VARCHAR(45),
        Src_ip VARCHAR(45),
        Dst_ip VARCHAR(45),
        Protocol VARCHAR(10),
        Src_port INT,
        Dst_port INT,
        Packet_size INT,
        Payload BLOB,
        TTL INT
    );
    """

    create_traffic_metric_table = """
    CREATE TABLE IF NOT EXISTS TRAFFIC_METRIC (
        Traffic_metric_id BIGINT AUTO_INCREMENT PRIMARY KEY,
        Time_bucket TIMESTAMP NOT NULL,
        Dst_ip VARCHAR(45),
        Packets_sent INT,
        Unique_src_ips INT,
        Bytes_sent BIGINT
    );
    """

    cursor.execute(create_device_table)
    cursor.execute(create_packet_table)
    cursor.execute(create_traffic_metric_table)

    db.commit()


def clear_db(db, cursor):
    query1 = "DROP TABLE PACKET"
    query2 = "DROP TABLE DEVICE"
    query3 = "DROP TABLE TRAFFIC_METRIC"

    cursor.execute(query1)
    cursor.execute(query2)
    cursor.execute(query3)

    db.commit()

    print("Database cleared.")


def connect_to_db():
    db = mysql.connector.connect(
        host="localhost",
        user="AdminNetPulse",
        password="@NetPulse2026",
        port=3306,
        database="netpulse_db"
    )
    return db, db.cursor()


def display_packet_in_db(cursor):
    query = "SELECT * FROM PACKET"
    cursor.execute(query)
    packets = cursor.fetchall()

    for packet in packets:
        print("Packet ID:", packet[0])
        print("Time:", datetime.fromtimestamp(packet[1]))
        print("Source MAC:", packet[2])
        print("Destination MAC:", packet[3])
        print("Source IP:", packet[4])
        print("Destination IP:", packet[5])
        print("Protocol:", packet[6])
        print("Source Port:", packet[7])
        print("Destination Port:", packet[8])
        print("Packet Size:", packet[9])
        print("TTL:", packet[11])
        print("-" * 40)


def store_packet_in_db(db, cursor, values):
    query = """
    INSERT INTO PACKET (
        Time_of_detection,
        Src_mac,
        Dst_mac,
        Src_ip,
        Dst_ip,
        Protocol,
        Src_port,
        Dst_port,
        Packet_size,
        Payload,
        TTL
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, values)
    db.commit()
    #print("Executed successfully.")
    

if __name__ == '__main__':
    db, cursor = connect_to_db()

    display_packet_in_db(cursor)

    cursor.close()
    db.close()