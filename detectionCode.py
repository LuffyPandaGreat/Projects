import pyshark
import warnings

warnings.filterwarnings("ignore")


ipAddressSRC = []
ipAddressSRC_unique = []
ipAddressDist = []
ipAddressDist_unique = []
threshold = 100


def sortIPaddress(copy):
    try:
        for cap1 in copy:
            if "IP" in cap1:
                ipAddressSRC.append(cap1.ip.src)
                ipAddressDist.append(cap1.ip.dst)
                
        for srcIP in ipAddressSRC:
            if srcIP not in ipAddressSRC_unique:
                ipAddressSRC_unique.append(srcIP)

        for dstIP in ipAddressDist:
            if dstIP not in ipAddressDist_unique:
                ipAddressDist_unique.append(dstIP)      
    except:
        pass


def ipAddress_Source_Frequncy_ddos():
    try:
        for sourceIP in ipAddressSRC_unique:
            srcFrequncy = 0
            for sourceIP1 in ipAddressSRC:
                if sourceIP1 == sourceIP:
                    srcFrequncy+=1
            if srcFrequncy >= threshold:
                print(f'DDOS detected from Source IP: {sourceIP}, Frequncy: {srcFrequncy}')
    except:
        pass

def ipAddress_Distination_Frequncy():
    try:
        for distinatinoIP in ipAddressDist_unique:
            disFrequncy = 0
            for distinatinoIP1 in ipAddressDist:
                if distinatinoIP1 == distinatinoIP:
                    disFrequncy+=1
            print(f'Distination IP: {distinatinoIP}, Frequncy: {disFrequncy}')
    except:
        pass

while(True):
    print("Scan for 5 seconds")
    liveCapture = pyshark.LiveCapture(interface="Wi-Fi", output_file="pyshark.pcap")
    try:
        liveCapture.sniff(timeout=5)
        liveCapture.close()
        with pyshark.FileCapture("pyshark.pcap", keep_packets=False) as file_capture:
            packetCapture = list(file_capture)
        copy = packetCapture
        sortIPaddress(copy)
        ipAddress_Source_Frequncy_ddos()
    except:
        pass
    
    
    


