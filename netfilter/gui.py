from firewall import Firewall
import sys
import os

"""
        gui.py                              Author: Rowland DePree


        A command console UI(user interface) design to interact with the firewall file to make it more user friendly.

"""
def main():
    """
    Main method.

    :return None
    """
    firewall = Firewall()
    print("Welcome to the Firewall Shell Program!")
    print("WARNING: This program deals with IP Tables and WILL overwrite existing iptable rules.")
    cont = raw_input("Do you still wish to proceed? [Y/N]")
    if cont.lower() == "n":
        print("Terminating Program.  Good-Bye.")
        sys.exit()
    elif cont.lower() != "n" and cont.lower() != "y":
        print("Invalid Option! \nTerminating Program!")
        sys.exit()
    else:
        cont = True
        print("Starting firewall shell....")
        firewall.start()
        print("Firewall shell is now running.....")
        while cont:
            print("Do you wish to....")
            print(
            "display tables[dispaly]\nblock port 25[block]\naccept forward[forward]\naccept icmp[icmp]\naccept input[input]\naccept protocol[protocol]\nredirect http[http]\nsource nat[nat]\nclose shell[close]\nrestart shell[restart]\ncommit[commit]\nclear[clear]")
            user_input = raw_input("Command: ")
            if user_input.lower() == "forward":
                question = raw_input("Do you wish to add an in and out interface? [Y/N]\n")
                if question.lower() == "y":
                    in_interface = raw_input("In Interface: ")
                    out_interface = raw_input("Out Interface: ")
                else:
                    in_interface = None
                    out_interface = None
                firewall.accept_forward(in_interface, out_interface)

            elif user_input.lower() == "icmp":
                question = raw_input("Do you wish to add an interface? [Y/N]\n")
                if question.lower() == "y":
                    interface = raw_input("Interface: ")
                else:
                    interface = None
                firewall.accept_icmp(interface)

            elif user_input.lower() == "input":
                question = raw_input("Do you wish to add an interface? [Y/N]\n")
                if question.lower() == "y":
                    interface = raw_input("Interface: ")
                else:
                    interface = None
                firewall.accept_input(interface)

            elif user_input.lower() == "protocol":
                interface = raw_input("Interface: ")
                port = raw_input("Port: ")
                question = raw_input("Do you wish to add an destination and source? [Y/N]\n")
                if question.lower() == "y":
                    dest = raw_input("Destination: ")
                    src = raw_input("Source: ")
                else:
                    dest = None
                    src = None
                firewall.accept_protocol(interface, port, dest, src)

            elif user_input.lower() == "http":
                interface = raw_input("Interface: ")
                proxy_port = raw_input("Proxy Port: ")
                firewall.redirect_http(interface, proxy_port)

            elif user_input.lower() == "display":
                print os.system("iptables -L -n")

            elif user_input.lower() == "block":
                print os.system("iptables -A OUTPUT -p tcp --dport 25 -j DROP")
                print "Port 25 Blocked for OUTGOING connections"
                print os.system("service iptables save")

            elif user_input.lower() == "nat":
                interface = raw_input("Interface: ")
                firewall.source_nat(interface)

            elif user_input.lower() == "close":
                print("Terminating shell....")
                firewall.stop()
                sys.exit()

            elif user_input.lower() == "restart":
                print("Restarting shell....")
                firewall.stop()
                firewall.start()

            elif user_input.lower() == "commit":
                print("Commiting changes...."),
                firewall.commit()
                print("Done")

            elif user_input.lower() == "clear":
                print("Clearing changes...."),
                firewall.clear()
                print("Done")

            else:
                print("INVALID OPTION!")

            qcont = raw_input("Do you wish to continue?[Y/N]\n")
            if qcont.lower() == "n":
                cont = False
            else:
                pass

"""
    Starts the main method
"""
if __name__ == "__main__":
    main()
