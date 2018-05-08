import pymysql
class mysql_connetcion:
    db=None;#链接数据库
    cursor=None;#数据库浮标
    db_execute="";#数据库执行语句
    db_data="";#查询数据库信息的打印值

    def db_connection(self):#链接数据库
        self.db=pymysql.connect("localhost","root","a379621573","packet_catcher");
        self.cursor=self.db.cursor();
    def db_fetche(self,cloumn,table):#查询数据库
        self.db_execute=("select %s from %s"%(cloumn,table))
        self.cursor.execute(self.db_execute);
        self.db_data=self.cursor.fetchall();
        print(self.db_data);


