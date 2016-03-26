# cisc_230_project

I need methods like these: divide them up and implement
    def accept_icmp(self, interface=None):
        self.print_message("allow selected icmp INPUT", interface)
        if self.__ipv6:
            self.filter.append_rule('INPUT', Rule(
                in_interface=interface,
                protocol='icmpv6',
                jump='ACCEPT'))
        else:
            types = ['echo-request',
                     'network-unreachable',
                     'host-unreachable',
                     'port-unreachable',
                     'fragmentation-needed',
                     'time-exceeded']

            for type in types:
                self.filter.append_rule('INPUT', Rule(
                    in_interface=interface,
                    protocol='icmp',
                    matches=[Match('icmp', "--icmp-type %s" % (type))],
                    jump='ACCEPT'))

    def accept_input(self, interface=None):
        self.print_message("allow INPUT", interface)
        self.filter.append_rule('INPUT', Rule(
            in_interface=interface,
            jump='ACCEPT'))

    def accept_protocol(self, interface, protocol, ports, destination=None, source=None):
        port_str = ','.join(ports)
        self.print_message("allow selected %s INPUT (ports: %s)" % (protocol, port_str), interface)
        self.filter.append_rule('INPUT', Rule(
            in_interface=interface,
            destination=destination,
            source=source,
            protocol=protocol,
            matches=[Match('state', '--state NEW'),
                     Match('multiport', "--destination-port %s" % port_str)],
            jump='ACCEPT'))
            
            
    def redirect_http(self, interface, proxy_port):
        if self.__ipv6: return
        self.print_message("redirect HTTP to port %s" % proxy_port, interface)
        self.nat.append_rule('PREROUTING', Rule(
            in_interface=interface,
            protocol='tcp',
            matches=[Match('tcp', '--dport 80')],
            jump=Target('REDIRECT', '--to-port %s' % proxy_port)))

    def set_default_policy(self):
        self.print_message("set default policy", None)
        self.filter.set_policy('INPUT', 'DROP')
        self.filter.append_rule('INPUT', Rule(
            matches=[Match('state', '--state ESTABLISHED,RELATED')],
            jump='ACCEPT'))
        self.filter.set_policy('OUTPUT', 'ACCEPT')
        self.filter.set_policy('FORWARD', 'DROP')
        self.filter.append_rule('FORWARD', Rule(
            matches=[Match('state', '--state ESTABLISHED,RELATED')],
            jump='ACCEPT'))

    def set_open_policy(self):
        self.print_message("set open policy", None)
        self.filter.set_policy('INPUT', 'ACCEPT')
        self.filter.set_policy('OUTPUT', 'ACCEPT')
        self.filter.set_policy('FORWARD', 'ACCEPT')