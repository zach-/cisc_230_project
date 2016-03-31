import os
import re
import subprocess

import netfilter.parser

"""
            table.py                                                Author: Zach Bricker

            A program to directly interface with IPTables

"""

class IptablesError(Exception):
    def __init__(self, command, message):
        """
        Constructor

        :param command
        :param message
        :return
        """
        self.command = command
        self.message = message

    def __str__(self):
        """
        Rewrites the built-in string method

        :return "command: %s\nmessage: %s" % (self.command, self.message)
        """
        return "command: %s\nmessage: %s" % (self.command, self.message)


class Table:

    __iptables_wait_option = None

    def __init__(self, name, auto_commit=True, ipv6=False):
        """
        Constructor

        :param name
        :param auto_commit
        :param ipv6
        :return
        """
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
        """
        Creates a chain

        :param chainname
        :return
        """
        self.__run_iptables(['-N', chainname])

    def delete_chain(self, chainname=None):
        """
        Deletes a chain

        :param chainname
        :return
        """
        args = ['-X']
        if chainname: args.append(chainname)
        self.__run_iptables(args)

    def flush_chain(self, chainname=None):
        """
        Fluchs a chain

        :param chainname
        :return
        """
        args = ['-F']
        if chainname: args.append(chainname)
        self.__run_iptables(args)

    def list_chains(self):
        """
        Lists all chains

        :param
        :return self.__get_chains().keys()
        """
        return self.__get_chains().keys()

    def rename_chain(self, old_chain_name, new_chain_name):
        """
        Renames a selected chain

        :param old_chain_name
        :param new_chain_name
        :return
        """
        self.__run_iptables(['-E', old_chain_name, new_chain_name])

    def get_policy(self, chainname):
        """
        Returns a policy

        :param chainname
        :return self.__get_chains()[chainname]['policy']
        """
        return self.__get_chains()[chainname]['policy']

    def set_policy(self, chainname, policy):
        """
        Sets a policy

        :param chainname
        :param policy
        :return
        """
        self.__run_iptables(['-P', chainname, policy])

    def append_rule(self, chainname, rule):
        """
        Addes a rule to the end of a chain

        :param chainname
        :param rule
        :return
        """
        self.__run_iptables(['-A', chainname] + rule.specbits())

    def delete_rule(self, chainname, rule):
        """
        Deletes a rule from a particular chian

        :param chainname
        :param rule
        :return
        """
        self.__run_iptables(['-D', chainname] + rule.specbits())

    def prepend_rule(self, chainname, rule):
        """
        Adds a rule to the beginning of the chain

        :param chainname
        :param rule
        :return
        """
        self.__run_iptables(['-I', chainname, '1'] + rule.specbits())

    def list_rules(self, chainname):
        """
        List all rules under a chain

        :param chainname
        :return netfilter.parser.parse_rules(data, chainname)
        """
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_rules(data, chainname)

    def commit(self):
        """
        Commits all changes

        :param
        :return
        """
        while len(self.__buffer) > 0:
            self.__run(self.__buffer.pop(0))

    def get_buffer(self):
        """
        Returns the buffer

        :param
        :return self.__buffer
        """
        return self.__buffer

    def __get_chains(self):
        """
        Returns a chain

        :param
        :return netfilter.parser.parse_chains(data)
        """
        data = self.__run([self.__iptables_save, '-t', self.__name, '-c'])
        return netfilter.parser.parse_chains(data)

    def __run_iptables(self, args):
        """
        Runs the IPTables

        :param args
        :return
        """
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
        """
        Runs the commands for IPTables

        :param cmd
        :return out
        """
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
