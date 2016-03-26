import os
import subprocess
import sys

from netfilter.rule import Rule, Match, Target
import netfilter.table


class Firewall:
    def __init__(self, auto_commit=True, ipv6=False):
        self.filter = netfilter.table.Table(
            name='filter',
            auto_commit=auto_commit,
            ipv6=ipv6)
        self.__ipv6 = ipv6
        self.__tables = [self.filter]
        if not ipv6:
            self.nat = netfilter.table.Table(
                name='nat',
                auto_commit=auto_commit,
                ipv6=ipv6)
            self.__tables.append(self.nat)

    def clear(self):
        for table in self.__tables:
            table.flush_chain()
            table.delete_chain()

    def commit(self):
        for table in self.__tables:
            table.commit()

    def get_buffer(self):
        buffer = []
        for table in self.__tables:
            buffer.extend(table.get_buffer())
        return buffer

    def run(self, args):
        prog = args[0]
        if len(args) < 2:
            self.usage(prog)
            return 1

        command = args[1]
        if command == "start":
            self.start()
        elif command == "stop":
            self.stop()
        elif command == "restart":
            self.stop()
            self.start()
        else:
            self.usage(prog)
            return 1
        return 0

    def start(self):
        self.clear()
        self.set_default_policy()
        self.accept_icmp()
        self.accept_input('lo')

    def stop(self):
        self.clear()
        self.set_open_policy()

    def usage(self, prog):
        sys.stderr.write("Usage: %s {start|stop|restart}\n" % prog)

    def accept_forward(self, in_interface=None, out_interface=None):
        self.print_message("allow FORWARD", in_interface)
        self.filter.append_rule('FORWARD', Rule(
            in_interface=in_interface,
            out_interface=out_interface,
            jump='ACCEPT'))

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

    def get_node(self):
        p = subprocess.Popen(["uname", "-n"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             close_fds=True)
        out, err = p.communicate()
        status = p.wait()
        # check exit status
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            raise Exception("uname failed : %s" % ''.join(err))
        node = out.strip()
        return node

    def print_message(self, msg, interface=None):
        if self.__ipv6:
            version = 'IPv6'
        else:
            version = 'IPv4'
        if interface:
            prefix = "interface %s" % interface
        else:
            prefix = "global"
        sys.stderr.write(" * %s %s: %s\n" % (version, prefix, msg))

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

    def source_nat(self, interface):
        if self.__ipv6:
            return
        self.print_message("enable SNAT", interface)
        self.nat.append_rule('POSTROUTING', Rule(
            out_interface=interface,
            jump='MASQUERADE'))


if __name__ == "__main__":
    sys.exit(Firewall().run(sys.argv))
