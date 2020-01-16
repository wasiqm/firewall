import pandas as pd
from ipaddress import ip_interface

class Firewall:
    def __init__(self, csv_path):
        df = pd.read_csv(csv_path, header=None)
        self.inbound_tcp = []
        self.outbound_tcp = []
        self.inbound_udp = []
        self.outbound_udp = []
        for index, row in df.iterrows():
            if row[0] == "inbound":
                if row[1] == "tcp":
                    self.inbound_tcp.append([row[2], row[3]])
                if row[1] == "udp":
                    self.inbound_udp.append([row[2], row[3]])
            if row[0] == "outbound":
                if row[1] == "tcp":
                    self.outbound_tcp.append([row[2], row[3]])
                if row[1] == "udp":
                    self.outbound_udp.append([row[2], row[3]])

    def is_port_in_range(self, port, port_rule):
        in_range = False
        if '-' not in port_rule:
            # if rule is just one port number, check if given port matches
            in_range = port == int(port_rule)
        else:
            # if rule is a range, check if given port is in the range
            port_range = port_rule.split('-')
            in_range = port in range(int(port_range[0]), int(port_range[1]) + 1)
        return in_range

    def is_ip_in_range(self, ip, ip_rule):
        in_range = False
        if '-' not in ip_rule:
            # if rule is just one ip address, check if given ip matches
            in_range = ip == ip_rule

        else:
            # if rule is a range, check if given ip is in the range            
            given_ip = ip_interface(ip)
            ip_range = ip_rule.split('-')
            range_lower = ip_interface(ip_range[0])
            range_upper = ip_interface(ip_range[1])

            in_range = range_lower <= given_ip and given_ip <= range_upper

        return in_range

    def accept_packet(self, direction, protocol, port, ip_address):
        if direction == "inbound" and protocol == "tcp":
            for rule_list in self.inbound_tcp:
                if self.is_port_in_range(port, rule_list[0]) and self.is_ip_in_range(ip_address, rule_list[1]):
                    return True
        elif direction == "inbound" and protocol == "udp":
            for rule_list in self.inbound_udp:
                if self.is_port_in_range(port, rule_list[0]) and self.is_ip_in_range(ip_address, rule_list[1]):
                    return True
        elif direction == "outbound" and protocol == "tcp":
            for rule_list in self.outbound_tcp:
                if self.is_port_in_range(port, rule_list[0]) and self.is_ip_in_range(ip_address, rule_list[1]):
                    return True
        elif direction == "outbound" and protocol == "udp":
            for rule_list in self.outbound_udp:
                if self.is_port_in_range(port, rule_list[0]) and self.is_ip_in_range(ip_address, rule_list[1]):
                    return True
        return False
    

if __name__ == '__main__':
    fw = Firewall("fw.csv")
    # sample inputs for testing  
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) #true
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) #true
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.5")) #true (edge case)
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.6")) #false (edge case)
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) #true
    print(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11")) #true (edge case)
    print(fw.accept_packet("outbound", "tcp", 9999, "192.168.10.11")) #false (edge case)
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")) #false
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92")) #false
    