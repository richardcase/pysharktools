import pyshark

capture = pyshark.LiveCapture(interface='enx8cae4cd66035',bpf_filter='arp')
for packet in capture.sniff_continuously():
    if  hasattr(packet, 'arp'):
        field_names = packet.arp._all_fields

        isgratuitous =' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'arp.isgratuitous'})
        if isgratuitous == '1':
            ip =  ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'arp.src.proto_ipv4'})
            mac = ' '.join(str(e) for e in {val for key, val in field_names.items() if key == 'arp.src.hw_mac'})
            print('gratuitous arp {0} = {1}'.format(ip, mac))