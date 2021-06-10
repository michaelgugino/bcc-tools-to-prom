import multiprocessing as mp
import time

from prometheus_client import start_http_server, Counter

from bcc_tools_to_prom.tcpretrans import *

def tcprtf(metricsd):
    tcprt = TCPRetrans(metricsd)
    tcprt.setup()
    tcprt.run()

def metricspf(metricsd):
    while 1:
        print("metricsd", metricsd)
        time.sleep(3)

def promf(metricsd):

    locald = dict()
    locald['tcpretrans4'] = 0
    locald['tcpretrans6'] = 0
    c4 = Counter('tcpretrans4', 'tcp retransmits IPv4')
    c6 = Counter('tcpretrans6', 'tcp retransmits IPv4')

    start_http_server(8000)

    while 1:
        if 'tcpretrans4' in metricsd and metricsd['tcpretrans4'] > locald['tcpretrans4']:
            c4.inc(metricsd['tcpretrans4'] - locald['tcpretrans4'])
            locald['tcpretrans4'] = metricsd['tcpretrans4']
        if 'tcpretrans6' in metricsd and metricsd['tcpretrans6'] > locald['tcpretrans6']:
            c4.inc(metricsd['tcpretrans6'] - locald['tcpretrans6'])
            locald['tcpretrans6'] = metricsd['tcpretrans6']
        # Add a small sleep here, we don't need to hot loop on updating this info
        time.sleep(3)



def main():
    with mp.Manager() as manager:
        metricsd = manager.dict()
        tcprtp = mp.Process(target=tcprtf, args=(metricsd,))
        # metricspp = mp.Process(target=metricspf, args=(metricsd,))
        promp = mp.Process(target=promf, args=(metricsd,))
        tcprtp.start()
        # metricspp.start()
        promp.start()
        tcprtp.join()

if __name__ == '__main__':
    main()
