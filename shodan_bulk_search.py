import csv
import shodan
import time
import pickle
import argparse
from tqdm import tqdm


def take_second(elem):
    return elem[1]


class ShodanAnalyze:
    def __init__(self, api_key, ip_list_file):
        self.ip_list_file = ip_list_file
        self.api_key = api_key

    def shodan_analyzer(self):
        api = shodan.Shodan(self.api_key)

        ip_list = []
        processed_ips = set()
        output = ""

        try:
            with open("processed_ips", "rb") as fp:  # for handling many IPs, this way processed IPs will be stored and reloaded
                processed_ips = pickle.load(fp)
        except FileNotFoundError:
            print("There aren't any stored IPs.")

        with open(self.ip_list_file, "r", encoding="utf-8") as fp:  # IP list should be provided here each for each line
            for line in fp:
                ip_list.append(line.strip())

        with open("output_file.csv", "w", newline='', encoding="UTF-8") as fp:  # output file
            csv_writer = csv.writer(fp, delimiter=",")
            for ip in tqdm(ip_list):
                if ip in processed_ips:
                    print("skipping ", ip)
                    continue
                try:
                    info = api.host(ip)
                    time.sleep(1)
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

                    output += ("{},{},{},{},{}\n".format(info["ip_str"],
                                                       info["os"],
                                                       asn,
                                                       " ".join(str(port) for port in info["ports"]),
                                                       " ".join(vulnerabilities)))
                    with open("processed_ips", "wb") as pfp:
                        processed_ips.add(ip)
                        pickle.dump(processed_ips, pfp)
                except shodan.exception.APIError as e:
                    time.sleep(1)
                    with open("processed_ips", "wb") as pfp:
                        processed_ips.add(ip)
                        pickle.dump(processed_ips, pfp)
                    print("For IP:" + ip + " this error is produced:" + str(e))

            first_line = output.partition('\n')[0]
            column_number = first_line.count(',') + 1
            for idx in range(column_number):
                words = []
                csv_words = []

                for row in output.splitlines():
                    row = row.split(",")
                    if idx == 0:
                        csv_writer.writerow(row)
                    csv_words = row[idx].split(" ")

                    for i in csv_words:
                        words.append(i)

                words_counted = []
                for i in words:
                    x = words.count(i)
                    words_counted.append((i, x))
                count_set = set(words_counted)
                loop_dict = {0: "ip_count", 1: "os_count", 2: "asn_count", 3: "port_count", 4: "vulnerability_count"}
                """Sorted by descending order of 2nd element which is occurence count and writes to csv"""
                with open(loop_dict[idx] + ".csv", 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerows(sorted(count_set, key=take_second,
                                            reverse=True))


if __name__ == '__main__':
    """Argparse for terminal execution"""
    ap = argparse.ArgumentParser()
    ap.add_argument("-l", "--list", required=True, help="Txt file that has list of IP addresses.")
    ap.add_argument("-s", "--shodan", required=True, help="Shodan API key")
    args = vars(ap.parse_args())
    """END argparse for terminal execution"""
    sh = ShodanAnalyze(args["shodan"], args["list"])
    sh.shodan_analyzer()
