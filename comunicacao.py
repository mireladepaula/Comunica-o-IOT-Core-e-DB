import pandas as pd
from pandas.core.indexes.range import RangeIndex
import sqlalchemy

engine = sqlalchemy.create_engine('mysql+pymysql://admin:sety#s3ty@database-telemetria.cdqxeoiuxk4q.us-east-1.rds.amazonaws.com:3306/iot_database')

df = pd.read_sql_table('messsage', engine)
df.head()


df = pd.read_sql_table('message', engine, columns=['first_name','last_name'])
df.head()

df = pd.sql_query('select *from message', engine)

df_index = pd.read_sql_query ('selec *from message', engine, index_col='emp_no')
df_index.head()

query = '''
SELECT  emp.first_name, 
        emp.last_name,
        emp.gender,
        depar.dept_name as departament_name,
        dept.from_date, 
        dept.to_date
FROM message emp
INNER JOIN dept_emp dept
ON emp.emp_no = dept.emp_no
INNER JOIN departaments depar
on dept.dept_no = depar.dept_no;

'''
df = pd.read_sql_query(query,engine)
df.head()
