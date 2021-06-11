import mariadb
from socket import ntohs


class Db:
    def __init__(self, hostname, user, password, database, host, port=3306):
        self.connection = mariadb.connect(user=user, password=password, database=database, host=host, port=port)
        self.hostname = hostname
        self.cursor = self.connection.cursor()

    def add_data(self, key: dict, data):
       # try:
            query = "insert into flows (hostname, ip_src, ip_dst, port_dst, syn_tx, rst_tx," \
                    " fin_tx, udp_tx, icmp_tx, tcp_tx, packet_rate_tx, throughput_tx, udp_tx_53)" \
                    " values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
            data = (
                self.hostname,
                int(key['ip_src']),
                int(key['ip_dst']),
                int(key['port_dst']),
                data.syn_tx,
                data.rst_tx,
                data.fin_tx,
                data.udp_tx,
                data.icmp_tx,
                data.tcp_tx,
                data.packet_rate_tx,
                data.throughput_tx,
                data.udp_tx_53

            )
            self.cursor.execute(query, data)
            self.connection.commit()
            result = self.cursor.rowcount
            # print(result)
        # except Exception as e:
        #     print(e)

