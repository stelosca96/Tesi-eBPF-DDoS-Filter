import mariadb


class Db:
    def __init__(self, user, password, database, host):
        self.connection = mariadb.connect(user=user, password=password, database=database, host=host)

        self.cursor = self.connection.cursor()

    def add_data(self, data: dict):
        try:
            query = "insert into flows (ip_src, ip_dst, port_dst, syn_tx, rst_tx, fin_tx)"\
                  " values (?, ?, ?, ?, ?, ?);"
            data = (
                data['ip_src'],
                data['ip_dst'],
                data['port_dst'],
                data['syn_tx'],
                data['rst_tx'],
                data['fin_tx'],
            )
            self.cursor.execute(query, data)
            self.connection.commit()
            result = self.cursor.rowcount
            print(result)
        except Exception as e:
            print(e)


if __name__ == '__main__':
    db = Db('root', 'ciao12345', 'anomaly_detection', '192.168.1.20')
    db.add_data(
        {
            'ip_src': 1,
            'ip_dst': 2,
            'port_dst': 3,
            'syn_tx': 4,
            'rst_tx': 5,
            'fin_tx': 6,
        }
    )
    print('ciao')