from scapy.all import sniff, IP, conf, show_interfaces
import subprocess
import geoip2.database
import sqlite3
conf.iface = "TAP-Windows Adapter V9"

class MakeRoute:
    def __init__(self):
        self.conn = sqlite3.connect('ip_addresses.sqlite')
        self.sqlite = self.conn.cursor()
        self.reader = None

    def modify_route(self, dst_ip):
        # 使用系统命令来修改路由表，将目标IP的网关设置为192.168.5.1，并设置为长期路由
        subprocess.run(['route', '-p', 'add', dst_ip, 'mask', '255.255.255.255', '192.168.5.1'])

    def packet_callback(self, packet):
            dst_ip = packet[IP].dst  # 获取目标IP地址
            try:
                _ = self.sqlite.execute('select * from ip_addresses where ip = ?', (dst_ip,)).fetchone()
            except Exception as e:
                _ = None
            
            if _ is None:
                try:
                    iso_code = self.reader.country(dst_ip).country.iso_code
                    if iso_code == 'CN':
                        self.modify_route(dst_ip)
                        print(f"{dst_ip} is from China, add route")
                except Exception as e:
                    print(e)
                try:
                    # 插入已经检查过的IP地址到数据库
                    self.sqlite.execute("INSERT INTO ip_addresses (ip) VALUES (?)", (dst_ip,))
                    self.conn.commit()
                    print(f"{dst_ip} is INSERTED")
                except Exception as e:
                    print(e)

    def start(self):
        self.sqlite.execute('''CREATE TABLE IF NOT EXISTS ip_addresses (ip TEXT)''')
        self.conn.commit()
        try:
            self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            sniff(prn=self.packet_callback, filter="ip", store=0)
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.sqlite.close()

route_maker = MakeRoute()
route_maker.start()