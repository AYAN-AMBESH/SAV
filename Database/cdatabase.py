import sqlite3

conn = sqlite3.connect('./hash.db')

cur = conn.cursor()

cur.execute('CREATE TABLE "check" ("SNum" int PRIMARY KEY,"Hashes" text);')
with open('./hash.txt','r') as f:
    file = f.readlines()
    print('inserting value:')
    print("------------------")
    print(len(file))
    for i in range(0,len(file)):
        conn.execute(f'INSERT INTO "check" VALUES("{i}","{file[i][:-1]}");')

# cur.execute('DROP TABLE "check"')
# cur.execute('SELECT COUNT(*) FROM "check"')
# print(cur.fetchall())
# cur.execute('SELECT Hashes FROM "check" WHERE SNum = 2')
# print(cur.fetchall())
# cur.execute('SELECT * FROM "check"')
# print(cur.fetchall())
conn.commit()
conn.close()