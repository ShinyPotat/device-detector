from scapy.all import sniff
import json, tweepy, time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

with open("./credentials.json") as f:
	credentials_dict = json.load(f)

consumer_key = credentials_dict.get("api_key")
consumer_secret = credentials_dict.get("api_secret_key")
access_token = credentials_dict.get("access_token")
access_token_secret = credentials_dict.get("access_token_secret")

auth = tweepy.OAuthHandler(consumer_key, consumer_secret)

auth.set_access_token(access_token, access_token_secret)

api = tweepy.API(auth)


interface = "Realtek RTL8822BE 802.11ac PCIe Adapter"
with open('./mac_addresses.json') as f:
  mac_dict = json.load(f)

def device_detector(packet):

	options = packet[4].options

	for opt in options:

			if type(opt) is tuple:
				option,value = opt

				if option == "hostname":
					hostname = value
	
	if packet.src in mac_dict.keys():
		print(packet.src + ' (' + bcolors.OKGREEN + mac_dict.get(packet.src) + bcolors.ENDC + ") se ha conectado!")
		api.send_direct_message(2363542539, packet.src + ' (' + mac_dict.get(packet.src) + ') se ha conectado!')
	if hostname in mac_dict.keys():
		print(hostname + ' (' + bcolors.OKGREEN + mac_dict.get(hostname) + bcolors.ENDC + " se ha conectado!")
		api.send_direct_message(2363542539, hostname + ' (' + mac_dict.get(hostname) + ') se ha conectado!')
		

if __name__ == "__main__":

	print(bcolors.HEADER + "Comenzando sniffing..." + bcolors.ENDC)

	while True:
		sniff(iface=interface, filter="port 67 or port 68", prn=device_detector, count = 1)
		time.sleep(5)