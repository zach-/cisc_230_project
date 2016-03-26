import os
import re
import subprocess

import netfilter.parser


class IptablesError(Exception):
    def __init__(self, command, message):
        self.command = command
        self.message = message

    def __str__(self):
        return "command: %s\nmessage: %s" % (self.command, self.message)


class Table:

    __iptables_wait_option = None

    def __init__(self, name, auto_commit=True, ipv6=False):
        self.auto_commit = auto_commit
        self.__name = name
        self.__buffer = []
        if ipv6:
            self.__iptables = 'ip6tables'
            self.__iptables_save = 'ip6tables-save'
        else:
            self.__iptables = 'iptables'
            self.__iptables_save = 'iptables-save'

    def create_chain(self, chainname):
        self.__run_iptables(['-N', chainname])

    def delete_chain(self, chainname=None):
        args = ['-X']
        if chainname: args.append(chainname)
        self.__run_iptables(args)

    def flush_chain(self, chainname=None):
        args = ['-F']
        if chainname: args.append(chainname)
        self.__run_iptables(args)

    def list_chains(self):
        return self.__get_chains().keys()

    def rename_chain(self, old_chain_name, new_chain_name):
        self.__run_iptables(['-E', old_chain_name, new_chain_name])

    def get_policy(self, chainname):
        return self.__get_chains()[chainname]['policy']

    def set_policy(self, chainname, policy):
        self.__run_iptables(['-P', chainname, policy])

    def append_rule(self, chainname, rule):
        self.__run_iptables(['-A', chainname] + rule.specbits())

    def delete_rule(self, chainname, rule):
        self.__run_iptables(['-D', chainname] + rule.specbits())

    def prepend_rule(self, chainname, rule):
        self.__run_iptables(['-I', chainname, '1'] + rule.specbits())

    def list_rules(self, chainname):
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_rules(data, chainname)

    def commit(self):
        while len(self.__buffer) > 0:
            self.__run(self.__buffer.pop(0))

    def get_buffer(self):
        return self.__buffer

    def __get_chains(self):
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_chains(data)

    def __run_iptables(self, args):
        if Table.__iptables_wait_option is None:
            # check whether iptables supports --wait
            try:
                self.__run([self.__iptables, '-L', '-n', '--wait'])
                Table.__iptables_wait_option = ['--wait']
            except:
                Table.__iptables_wait_option = []

        cmd = [self.__iptables] + Table.__iptables_wait_option + ['-t', self.__name] + args
        if self.auto_commit:
            self.__run(cmd)
        else:
            self.__buffer.append(cmd)

    def __run(self, cmd):
        p = subprocess.Popen(cmd,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             close_fds=True)
        out, err = p.communicate()
        status = p.wait()
        # check exit status
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status):
            if not re.match(r'(iptables|ip6tables): Chain already exists', err):
                raise IptablesError(cmd, err)
        return out
