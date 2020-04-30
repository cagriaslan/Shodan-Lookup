import shodan
import time
import pickle
from tqdm import tqdm

api = shodan.Shodan('APIKEY')

ip_list = []
processed_ips = set()

try:
    with open("processed_ips", "rb") as fp:  # for handling many IPs, this way processed IPs will be stored and reloaded
        processed_ips = pickle.load(fp)
except FileNotFoundError:
    print("There aren't any stored IPs.")

with open("ip_list", "r", encoding="utf-8") as fp:  # IP list should be provided here each for each line
    for line in fp:
        ip_list.append(line.split(" ")[1].strip())

with open("output_file", "a", encoding="UTF-8") as fp:  # output file
    for ip in tqdm(ip_list):
        if ip in processed_ips:
            continue
        try:
            info = api.host(ip)
            time.sleep(5)
            # parsed = json.dumps(info)
            # parsed = json.loads(parsed)
            # print(json.dumps(parsed, indent=4, sort_keys=True))
            try:
                vulnerabilities = info["vulns"]
            except KeyError as e:
                print("No vulns for {}".format(info["ip_str"]))
                vulnerabilities = ["None"]
            try:
                asn = info["asn"]
            except KeyError as e:
                asn = "none"
            fp.write("{},{},{},{},{}\n".format(info["ip_str"],
                                               info["os"],
                                               asn,
                                               " ".join(str(port) for port in info["ports"]),
                                               " ".join(vulnerabilities)))
            with open("processed_ips", "wb") as pfp:
                processed_ips.add(ip)
                pickle.dump(processed_ips, pfp)
        except shodan.exception.APIError as e:
            time.sleep(5)
            with open("processed_ips", "wb") as pfp:
                processed_ips.add(ip)
                pickle.dump(processed_ips, pfp)
            print("For IP:" + ip + " this error is produced:" + str(e))
