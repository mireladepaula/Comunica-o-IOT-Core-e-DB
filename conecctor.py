import mysql.connector


con = mysql.connector.connect (host='database-telemetria.cdqxeoiuxk4q.us-east-1.rds.amazonaws.com', database='iot_database', user='admin', passwd='sety#s3ty')
if con.is_connected():
    db_info = con.get_server_info()
    print("Conexão com servidor realizada com sucesso", db_info)
    cursor = con.cursor()
    cursor.execute ("SELECT * FROM message")
    query = '''
SELECT Messagem
'''
    linha = cursor.fetchone()
    print ("Conectado ao banco de dados", linha)
if con.is_connected():
    cursor.close()
    print("Conexão encerrada com o banco de dados")

    