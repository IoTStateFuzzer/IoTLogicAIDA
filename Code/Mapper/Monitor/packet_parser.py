import json
import pyshark
import os
import csv
import re
from collections import defaultdict
from collections import OrderedDict
import time

from Scripts import get_ips
from Scripts import format_tools
from Logger import mlog
from Mapper.Monitor.protocol_feature import feature_dict
from Config.device_appium_config import get_phone_and_device_ip_list, get_phone_ip_list, get_phone_and_device_ip, get_user_distance_and_device_ip_list
from Config.config_file import abstract_str, threshold_among_each_kind_of_action, threshold_in_one_op, threshold_of_random

ROOT_PATH = os.path.dirname(__file__)
PACKET_ROOT_PATH = f"{ROOT_PATH}/packets/"
SELECTED_FEATURE_TXT = "0selected_features.txt"
FILTERED_FEATURE_TXT = "0filtered_features.txt"
FEATURE_STATIC_JSON = "0feature_static.json"
PAYLOAD_PATTERN_JSON = "0payload_pattern.json"
PAYLOAD_STATIC_JSON = "0payload_static.json"
CLASSIFY_RESULT_JSON = "0classify_result.json"

protocol_filter_expression = "(http or mqtt or (pppp and !icmp) or (udp and !dns and !mdns and !icmp and !bootp and !coap and !ntp and !ssdp and !rx and !quic) or ((tcp and tcp.len>0 and !tls) and (!tcp.analysis.flags or tcp.analysis.out_of_order)))"

specific_response_op_name_list = {
    "user1|local|AddDevice": -1
}
specific_response_flag = True

protocol_to_be_filtered = ["http", "udp", "tcp"]

fieldnames_of_csv = []
for protocol_name in feature_dict.keys():
    fieldnames_of_csv.extend(feature_dict[protocol_name])
ori_len_of_fieldnames = len(fieldnames_of_csv)


def save_feature_in_csv_file(feature_list, csv_path):
    """
    :param feature_list:
    :param csv_path: path to csv file
    """
    with open(csv_path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames_of_csv)
        writer.writeheader()
        writer.writerows(feature_list)


def get_header_features(pcap: pyshark.FileCapture, pcapng_file_path: str, dns_mapping_list: list, use_old_ip_version=False, **save_file_param):
    """
    For a given pcap file, extract the features of all headers
    :param pcap: Given pcap file
    :param pcapng_file_path: The name of pcapng file, such as /path/to/manually.pcapng
    :param dns_mapping_list: Map ip addresses to domain names
    :param use_old_ip_version: if False, get phone ip dynamic; else get ip for test
    :param save_file_param: save_csv_flag:bool, op_file_name:str such as INVITE.txt, save_payload_flag:bool
    :return : header feature list
    """
    # packet number and payload
    number_payload_dict = {}

    # get phone and device ip
    phone_device_ip_dict = get_phone_and_device_ip(use_old_ip_version)
    ip_inst_dict = {}
    for user in phone_device_ip_dict:
        if user == "devices":
            for dev_ip_index in range(len(phone_device_ip_dict[user])):
                ip_inst_dict[phone_device_ip_dict[user][dev_ip_index]] = f"device_{dev_ip_index}"
        else:
            for distance in phone_device_ip_dict[user]:
                ip_inst_dict[phone_device_ip_dict[user][distance]] = f"{user}_{distance}"

    # get black ip
    with open(f"{ROOT_PATH}/black_list.json", "r") as black_file:
        black_dict = json.load(black_file)
        black_ip_list = black_dict["ip"]

    pcap_feature_dict_list = []
    dns_update_flag = False

    try:
        for packet in pcap:
            # if "ip" not in packet, or ip in black ip list,
            # or transport layer is tcp but len=0 or is the segment of tcp
            if ((not packet.get_multiple_layers("ip"))
                    # or (packet.ip.src in black_ip_list or packet.ip.dst in black_ip_list)
                    or (format_tools.pattern_matching(packet.ip.src, black_ip_list) or format_tools.pattern_matching(packet.ip.dst, black_ip_list))
                    or (packet.transport_layer.lower() == "tcp" and ("segment_data" in packet.tcp.field_names and packet.tcp.flags != "0x00000018"))):
                continue

            packet_feature_dict = {}
            # get basic info
            packet_feature_dict["number"] = packet.number
            packet_feature_dict["src"] = packet.ip.src
            packet_feature_dict["dst"] = packet.ip.dst
            if packet_feature_dict["src"] in black_ip_list or packet_feature_dict["dst"] in black_ip_list:
                continue

            # if dst is phone or device, change by name
            if packet_feature_dict["dst"] in ip_inst_dict.keys():
                packet_feature_dict["domain"] = ip_inst_dict[packet_feature_dict["dst"]]
            else:
                packet_feature_dict["domain"] = format_tools.get_domain_by_ip(packet.ip.dst, dns_mapping_list)
                # maybe current ip->domain is not in history, but it appears at this time
                if packet_feature_dict["domain"] == packet_feature_dict["dst"] and packet_feature_dict["dst"] not in dns_mapping_list:
                    print(packet.number, packet_feature_dict["domain"])
                    cur_packet_parse_dns_list = parse_dns_and_get_ip_domain(pcapng_file_path)
                    dns_mapping_list = cur_packet_parse_dns_list
                    dns_update_flag = True
                    packet_feature_dict["domain"] = format_tools.get_domain_by_ip(packet_feature_dict["dst"], cur_packet_parse_dns_list)

            packet_feature_dict["srcport"] = packet[packet.transport_layer].srcport if packet.ip.src not in ip_inst_dict.keys() else None
            packet_feature_dict["dstport"] = packet[packet.transport_layer].dstport if packet.ip.dst not in ip_inst_dict.keys() else None

            # get features for each protocol
            for protocol_name in feature_dict.keys():
                if protocol_name in ["record", "common"]:
                    continue
                if packet.get_multiple_layers(protocol_name):
                    if "protocol" not in packet_feature_dict:
                        packet_feature_dict["protocol"] = protocol_name
                    else:
                        continue
                    cur_layer = packet[protocol_name]
                    for field_name in feature_dict[protocol_name]:
                        packet_feature_dict[field_name] = format_tools.simply_format_header_feature(cur_layer.get_field(field_name))
                        # packet_feature_dict[field_name] = cur_layer.get_field(field_name)
                        if field_name == "request_uri" and packet.get_multiple_layers('urlencoded-form'):
                            context_headers = packet.http.file_data.split('&')
                            for item in context_headers:
                                if re.match(r"^a=", item):
                                    packet_feature_dict[field_name] = f"{packet_feature_dict[field_name]}/{item[2:].replace('.', '/')}"
                                    break

                    # if this packet is the response of any http packet
                    if "response" in cur_layer.field_names and "request_in" in cur_layer.field_names:
                        domain = cur_layer.response_for_uri.split("://")[-1].split("/")[0]
                        uri = cur_layer.response_for_uri.split("://")[-1][len(domain):]
                        packet_feature_dict["domain"] = domain
                        temp_port = packet_feature_dict['srcport']
                        packet_feature_dict['srcport'] = packet_feature_dict["dstport"]
                        packet_feature_dict['dstport'] = temp_port

                        list_len = len(pcap_feature_dict_list)
                        for index in range(list_len - 1, -1, -1):
                            if pcap_feature_dict_list[index]["number"] == cur_layer.request_in:
                                for field_name in feature_dict[protocol_name]:
                                    packet_feature_dict[field_name] = pcap_feature_dict_list[index][field_name]
                                pcap_feature_dict_list.pop(index)
                                break

                else:
                    for field_name in feature_dict[protocol_name]:
                        packet_feature_dict[field_name] = None
            # ignore if len of tcp is 0
            if ((check_if_current_feature_dict_in_black_dict(packet_feature_dict, black_dict))):
                continue

            # if not merge_flag:
            pcap_feature_dict_list.append(packet_feature_dict)

            # get payload
            try:
                number_payload_dict[packet_feature_dict["number"]] = get_payload_from_packet(packet)
            except Exception:
                mlog.log_func(mlog.ERROR, "Exception from packet_parser.get_header_features.add, please check 'number'")
                return -1, -1, -1

    except Exception:
        mlog.log_func(mlog.ERROR, "Exception from packet_parser.get_header_features")
        time.sleep(0.3)
        return -1, -1, -1

    # save payload
    if "save_csv_flag" in save_file_param and save_file_param["save_csv_flag"]:
        if "op_file_path" in save_file_param:
            # if "save_payload_flag" in save_file_param:
            #     fieldnames_of_csv.insert(0, "payload")

            # save csv file
            save_feature_in_csv_file(pcap_feature_dict_list, save_file_param["op_file_path"])
            # if "save_payload_flag" in save_file_param:
            #     fieldnames_of_csv.pop(0)
        else:
            mlog.log_func(mlog.ERROR, "Parameter \"op_file_path\" is missing, could not save in csv file")

    return pcap_feature_dict_list, dns_update_flag, number_payload_dict


def get_payload_from_packet(packet):
    return_str = None

    if packet.transport_layer.lower() == "udp":
        if packet.get_multiple_layers("pppp"):
            # pppp
            if "payload" in packet.pppp.field_names:
                if int(packet.pppp.message_header.message_size) > 120 or int(packet.pppp.message_header.message_size) < 10:
                    return_str = "pppp_stream_payload"
                else:
                    return_str = packet.pppp.get_field("payload")
        else:
            # just udp
            return_str = packet.udp.get_field("payload")
        return return_str if return_str else "payload_is_None"
    else:
        if packet.get_multiple_layers("http"):
            # http
            if "file_data" in packet.http.field_names:
                # with file_data
                return_str = packet.http.file_data
            else:
                # just return code
                return_str = packet.http.response_code if "response_code" in packet.http.field_names else ""
        elif packet.get_multiple_layers("mqtt"):
            # mqtt
            # return_str = format_tools.hex_to_ascii(packet.mqtt.msg) if "msg" in packet.mqtt.field_names else ""
            return_str = packet.mqtt.get_field("msg") if "msg" in packet.mqtt.field_names else ""
            return return_str if return_str else "payload_is_None"
        else:
            # just tcp
            return_str = packet.tcp.get_field("payload")
            return return_str if return_str else "payload_is_None"

    return format_tools.remove_string_by_some_pattern(str(return_str)) if return_str else "payload_is_None"


def split_list_by_length(strings):
    length_dict = defaultdict(list)

    for temp_index in range(len(strings)):
        if strings[temp_index]:
            str_split_list = strings[temp_index].split(",")
            split_len_list = [str(len(item)) for item in str_split_list]
            length = "|".join(split_len_list)
            # length = len(strings[temp_index])
            length_dict[length].append(strings[temp_index])
        else:
            length_dict['0'].append(strings[temp_index])

    result = list(length_dict.values())

    for i in range(len(result)):
        result[i] = format_tools.deduplicate_for_list(result[i])

    return result


def parse_dns_and_get_ip_domain(pcapng_file_path, keep_file_flag=True):
    """
    Parse the packet about the DNS in the given pcapng file and get a mapping of the ip-domain name
    :param pcapng_file_path: packet under parsing
    :return : mapping list
    """
    mlog.log_func(mlog.LOG, f"Parsing DNS packets of pcapng file: <{pcapng_file_path.split('/')[-1]}>")
    dns_mapping_list = []

    def parse_dns_response(dns_layer):
        cur_mapping = {}
        reflect_cname_mapping = {}
        count_answers = int(dns_layer.count_answers)
        dns_layer = str(dns_layer).replace("\t", "").split("\n")
        if "Answers" in dns_layer:
            start_index = dns_layer.index("Answers") + 1
            for item in dns_layer[start_index: start_index + count_answers]:
                domain = item.split(":")[0]
                result = item.split()[-1]
                if "CNAME" in item:
                    reflect_cname_mapping[result] = domain
                elif 'A' in item:
                    cur_mapping[result] = domain
            for ip in cur_mapping:
                while cur_mapping[ip] in reflect_cname_mapping:
                    cur_mapping[ip] = reflect_cname_mapping[cur_mapping[ip]]

        return cur_mapping

    cap = pyshark.FileCapture(pcapng_file_path, display_filter="dns")
    for packet in cap:
        if 'resp_name' in packet.dns.field_names:
            dns_layer = packet.dns
            parse_result = parse_dns_response(dns_layer)
            if parse_result not in dns_mapping_list:
                dns_mapping_list.append(parse_result)
    cap.close()

    # if using history record
    if keep_file_flag:
        total_dict = dict()
        for dns_item in dns_mapping_list:
            for key, value in dns_item.items():
                total_dict[key] = value

        dns_mapping_file_path = ROOT_PATH + "/dns_mapping.json"
        if os.path.exists(dns_mapping_file_path) and os.path.getsize(dns_mapping_file_path):
            with open(dns_mapping_file_path, "r") as dns_file_handle:
                history_dns_record = json.load(dns_file_handle)
            for key, value in total_dict.items():
                history_dns_record[key] = value
            with open(dns_mapping_file_path, "w") as dns_file_handle:
                dns_file_handle.write(json.dumps(history_dns_record, indent=4))
            return history_dns_record

        else:
            with open(dns_mapping_file_path, "w") as dns_file_handle:
                dns_file_handle.write(json.dumps(total_dict, indent=4))
            return total_dict
    else:
        return dns_mapping_list


def get_dns_result():
    with open(f"{ROOT_PATH}/dns_mapping.json", "r") as dns_file:
        dns_list = json.load(dns_file)
    return dns_list


def get_key_from_uri(uri_str):
    return "|".join([str(len(x)) for x in uri_str.split("/")])


def get_url_pattern(dataset) -> dict:
    """
    get http-url pattern for dataset.
    :param dataset: dataset for analyse
    :return: pattern dictionary
    """
    result_dict = {}
    dataset_path = PACKET_ROOT_PATH + dataset + "/"
    all_packet_folder_list = os.listdir(dataset_path)
    for distance_folder in all_packet_folder_list:
        if not os.path.isdir(dataset_path + distance_folder):
            continue
        distance_folder_path = dataset_path + distance_folder + "/"
        under_distance_files = os.listdir(distance_folder_path)

        for user_pcap_txt in under_distance_files:
            if not os.path.isdir(distance_folder_path + user_pcap_txt):
                continue
            user_folder_path = distance_folder_path + user_pcap_txt + "/"
            action_folders = os.listdir(user_folder_path)

            for op in action_folders:
                if not os.path.isdir(user_folder_path + op):
                    continue

                action_folder_path = user_folder_path + op + "/"
                file_list = os.listdir(action_folder_path)

                # read from csv files
                for file in file_list:
                    if op not in file or file.split(".")[-1] != "csv":
                        continue
                    with open(action_folder_path + file, "r") as f_handle:
                        reader = csv.reader(f_handle)
                        header = next(reader)
                        domain_index = list(header).index("domain")
                        uri_index = list(header).index("request_uri")
                        for line in list(reader):
                            if line[uri_index] and line[domain_index]:
                                if line[domain_index] not in result_dict:
                                    result_dict[line[domain_index]] = {}
                                format_uri_key = get_key_from_uri(line[uri_index])
                                if format_uri_key not in result_dict[line[domain_index]]:
                                    result_dict[line[domain_index]][format_uri_key] = []
                                if line[uri_index] not in result_dict[line[domain_index]][format_uri_key]:
                                    result_dict[line[domain_index]][format_uri_key].append(line[uri_index])

    pattern_dict = {}
    # get uri pattern
    for domain in result_dict.keys():
        for key, uri_list in result_dict[domain].items():
            new_pattern_list = format_tools.get_patterns_for_cases(uri_list, threshold=threshold_of_random)
            record_flag = False
            for pattern_index in range(len(new_pattern_list)):
                pattern_str = "".join(new_pattern_list[pattern_index])
                if abstract_str in pattern_str:
                    record_flag = True
            if record_flag:
                # add to pattern dictionary
                if domain not in pattern_dict:
                    pattern_dict[domain] = dict()
                if key not in pattern_dict[domain]:
                    pattern_dict[domain][key] = []
                pattern_dict[domain][key].extend(new_pattern_list)

    with open(dataset_path + "0uri_pattern.json", "w") as f:
        f.write(json.dumps(pattern_dict, indent=4))

    return pattern_dict


def modify_dataset_by_pattern(dataset, pattern):
    def modify_csv_by_pattern(csv_path, pattern_dict):
        """

        """
        flag = False
        with open(csv_path, "r") as f_handle:
            reader = csv.reader(f_handle)
            line_copy = list(reader).copy()
            header = line_copy[0]
            domain_index = list(header).index("domain")
            uri_index = list(header).index("request_uri")
            for line in line_copy[1:]:
                if line[domain_index] in pattern_dict:
                    if line[uri_index] and get_key_from_uri(line[uri_index]) in pattern_dict[line[domain_index]]:
                        pattern_oir_list_mode = format_tools.pattern_matching(line[uri_index], pattern_dict[line[domain_index]][get_key_from_uri(line[uri_index])])
                        if pattern_oir_list_mode:
                            line[uri_index] = "".join(pattern_oir_list_mode)
                            flag = True
        if flag:
            with open(csv_path, "w") as f_handle:
                writer = csv.writer(f_handle)
                writer.writerows(line_copy)

    dataset_path = PACKET_ROOT_PATH + dataset + "/"
    all_packet_folder_list = os.listdir(dataset_path)
    for distance_folder in all_packet_folder_list:
        if not os.path.isdir(dataset_path + distance_folder):
            continue
        distance_folder_path = dataset_path + distance_folder + "/"
        under_distance_files = os.listdir(distance_folder_path)

        for user_pcap_txt in under_distance_files:
            if not os.path.isdir(distance_folder_path + user_pcap_txt):
                continue
            user_folder_path = distance_folder_path + user_pcap_txt + "/"
            action_folders = os.listdir(user_folder_path)

            for op in action_folders:
                if not os.path.isdir(user_folder_path + op):
                    continue
                action_folder_path = user_folder_path + op + "/"
                file_list = os.listdir(action_folder_path)

                # read from csv files
                for file in file_list:
                    if op not in file or file.split(".")[-1] != "csv":
                        continue
                    modify_csv_by_pattern(action_folder_path + file, pattern)


def check_if_current_feature_dict_in_black_dict(ori_dict: dict, black_dict: dict) -> bool:
    for black_key in black_dict:
        if black_key in ori_dict:
            if ori_dict[black_key] and ori_dict[black_key] in black_dict[black_key]:
                return True
        elif black_key == "ip":
            if ori_dict["src"] in black_dict[black_key] or ori_dict["dst"] in black_dict[black_key]:
                return True
        elif black_key == "full_feature":
            continue
    return False


def pre_parse(dataset_list: list, use_manual_ip=False, parse_dns=True, execute_module1=True):
    """
    Analyse dataset and learn how to extract an abstract response for LearnLib.
    :param dataset_list:
    """
    mlog.log_func(mlog.LOG, "Start pre-parsing...")
    mlog.log_func(mlog.LOG, "Dataset:  ")
    mlog.log_list_func(mlog.LOG, dataset_list)

    # get black list
    with open(ROOT_PATH + "/black_list.json", "r") as bf:
        black_dict = json.load(bf)
    mlog.log_func(mlog.LOG, "Blacklist: ")
    mlog.log_dict_func(mlog.LOG, black_dict)

    phone_device_ip_dict = get_phone_and_device_ip(use_manual_ip)
    phone_ip_list = get_phone_ip_list(use_manual_ip)
    phone_device_ip_list = get_phone_and_device_ip_list(use_manual_ip)
    mlog.log_func(mlog.LOG, "Phone and devices ip list: ")
    mlog.log_dict_func(mlog.LOG, phone_device_ip_dict)

    for dataset in dataset_list:
        mlog.log_func(mlog.LOG, f"Current dataset: {dataset}")

        """
            ================================ module 0 ================================
            Parse and load dns
        """

        dataset_path = PACKET_ROOT_PATH + dataset + "/"
        all_packet_folder_list = os.listdir(dataset_path)

        # get the knowledge of dns mapping from ip to domain
        if parse_dns:
            for distance_folder in all_packet_folder_list:
                if not os.path.isdir(dataset_path + distance_folder):
                    continue
                distance_folder_path = dataset_path + distance_folder + "/"  # dataset/local/
                under_distance_files = os.listdir(distance_folder_path)

                # parse DNS message and save
                for user_pcap_txt in under_distance_files:
                    if "pcapng" not in user_pcap_txt:
                        continue
                    parse_dns_and_get_ip_domain(distance_folder_path + user_pcap_txt)

        # load dns info
        with open(ROOT_PATH + "/dns_mapping.json", "r") as dns_file:
            dns_mapping_list = json.load(dns_file)

        if execute_module1:
            """
                ================================ module 1 ================================
                Read pcapng files and extract header features.
                Save features in corresponding csv file.
            """
            mlog.log_func(mlog.LOG, "Start module 1: reading pcapng files and extracting features")

            # parse packet and extract header features
            for distance_folder in all_packet_folder_list:
                if not os.path.isdir(dataset_path + distance_folder):
                    continue
                distance_folder_path = dataset_path + distance_folder + "/"  # dataset/local/
                under_distance_files = os.listdir(distance_folder_path)
                for user_pcap_txt in under_distance_files:
                    if not os.path.isdir(distance_folder_path + user_pcap_txt):
                        continue
                    user_folder_path = distance_folder_path + user_pcap_txt + "/"  # dataset/distance/user/
                    action_folders = os.listdir(user_folder_path)

                    for action_folder in action_folders:
                        if not os.path.isdir(user_folder_path + action_folder):
                            continue

                        mlog.log_func(mlog.LOG, f"-Action: {distance_folder}|{user_pcap_txt}|{action_folder}")

                        # get action folder
                        abs_action_folder = user_folder_path + action_folder + "/"  # dataset/local/user1/action/
                        file_list = [x for x in os.listdir(abs_action_folder) if "txt" in x and action_folder in x]
                        cur_action_count = len(file_list)

                        # for each pcapng file, get its feature.csv file
                        for action_index in range(cur_action_count):
                            item = file_list[action_index]
                            mlog.log_func(mlog.LOG, f"{action_index + 1}/{cur_action_count} Reading file: {item}", t_count=1)
                            with open(abs_action_folder + item, "r") as f:
                                lines = f.readlines()
                                pcap_name = lines[0].replace("\n", "")
                                start_time = lines[1].replace("\n", "")
                                end_time = lines[2].replace("\n", "")

                            # get device ip list and current user|distance ip for filter condition
                            pd_dict = phone_device_ip_dict["devices"].copy()
                            pd_dict.append(phone_device_ip_dict[user_pcap_txt][distance_folder])

                            # get white ip list
                            merged_ip_list = get_ips.merge_manual_ip_list(phone_device_ip_dict["devices"].copy(), database)

                            # read pcap file and extract features
                            keylog_file = pcap_name.split('.')[0] + ".txt"
                            cur_wireshark_filter_expression = format_tools.get_merged_wireshark_filter_expression([
                                format_tools.get_wireshark_filter_by_timestamp(start_time, end_time),
                                protocol_filter_expression,
                                format_tools.get_wireshark_filter_expression_by_blackname_list_dict(black_dict),
                                format_tools.get_wireshark_filter_expression_by_selected_ip_list(pd_dict),
                                format_tools.get_wireshark_filter_expression_by_selected_ip_list(merged_ip_list)
                            ])

                            # print(cur_wireshark_filter_expression)

                            pcap = pyshark.FileCapture(distance_folder_path + pcap_name, display_filter=cur_wireshark_filter_expression,
                                                       override_prefs={'ssl.keylog_file': distance_folder_path + keylog_file})
                            csv_path = abs_action_folder + item.split(".")[0] + f"_{distance_folder}.csv"
                            get_header_features(pcap, distance_folder_path + pcap_name, dns_mapping_list, use_old_ip_version=use_manual_ip, save_csv_flag=True, op_file_path=csv_path)
                            pcap.close()

                            # if current action is remote, read local pcap file
                            if distance_folder == "remote":
                                pcap_name = f"{'_'.join(pcap_name.split('_')[:-1])}_local.pcapng"
                                local_pcap_file_path = f"{dataset_path}/local/{pcap_name}"
                                local_txt_file_path = f"{local_pcap_file_path[:-6]}txt"

                                local_wireshark_expression = format_tools.get_merged_wireshark_filter_expression([
                                    format_tools.get_wireshark_filter_by_timestamp(start_time, end_time),
                                    format_tools.get_wireshark_filter_expression_by_selected_ip_list(pd_dict),
                                    protocol_filter_expression
                                ])

                                # read
                                pcap = pyshark.FileCapture(local_pcap_file_path,
                                                           display_filter=local_wireshark_expression,
                                                           override_prefs={'ssl.keylog_file': local_txt_file_path})
                                csv_path = abs_action_folder + item.split(".")[0] + "_local.csv"
                                get_header_features(pcap, local_pcap_file_path, dns_mapping_list,
                                                    use_old_ip_version=use_manual_ip, save_csv_flag=True,
                                                    op_file_path=csv_path)
                                pcap.close()
                            elif distance_folder == "local" and os.path.exists(f"{abs_action_folder}/{item.split('|')[-1].split('.')[0]}"):
                                direct_pcap_path = f"{abs_action_folder}/{item.split('|')[-1].split('.')[0]}"
                                csv_path = f"{direct_pcap_path}_direct.csv"
                                pcap = pyshark.FileCapture(direct_pcap_path, display_filter=protocol_filter_expression)
                                get_header_features(pcap, direct_pcap_path, dns_mapping_list,
                                                    use_old_ip_version=use_manual_ip, save_csv_flag=True,
                                                    op_file_path=csv_path)
                                pcap.close()

                            # write filter expression in txt file
                            while len(lines) > 3:
                                lines.pop(-1)
                            lines.append("\n" + cur_wireshark_filter_expression)
                            with open(abs_action_folder + item, "w") as f:
                                f.writelines(lines)

            # read dataset and get pattern
            mlog.log_func(mlog.LOG, f"Get url pattern for dataset: {dataset}")
            url_pattern = get_url_pattern(dataset)
            modify_dataset_by_pattern(dataset, url_pattern)

        """
            ================================ module 2 ================================
            Filter packets which appear more than threshold times among all actions.
        """
        mlog.log_func(mlog.LOG, "Start module 2: filtering packet which appears more than threshold times among all actions.")

        feature_filter_by_general_list = []

        # add from black list
        if "full_feature" in black_dict:
            feature_filter_by_general_list.extend(black_dict["full_feature"])

        # Collect statistics on features whose number of occurrences exceeds the threshold
        feature_ops_dict = {}
        count_of_op = 0

        # get feature aggregation from each csv and static appearance time
        for distance_folder in all_packet_folder_list:
            if not os.path.isdir(dataset_path + distance_folder):
                continue

            distance_folder_path = dataset_path + distance_folder + "/"
            under_distance_files = os.listdir(distance_folder_path)

            for user_pcap_txt in under_distance_files:
                if not os.path.isdir(distance_folder_path + user_pcap_txt):
                    continue
                user_folder_path = distance_folder_path + user_pcap_txt + "/"
                action_folders = os.listdir(user_folder_path)

                for action in action_folders:
                    if not os.path.isdir(user_folder_path + action):
                        continue

                    abs_action_folder = user_folder_path + action + "/"

                    full_action_name = f"{distance_folder}|{user_pcap_txt}|{action}"
                    count_of_op += 1
                    file_list = os.listdir(abs_action_folder)

                    for cur_file in file_list:
                        # find csv file
                        if cur_file[-3:] != "csv":
                            continue

                        # read csv file
                        with open(abs_action_folder + cur_file, "r") as file:
                            reader = csv.reader(file)
                            header = next(reader)
                            for line in list(reader):
                                cur_line_feature = "|".join(line[header.index("domain"):])

                                # filter by black list
                                is_black = False
                                for black_key in black_dict.keys():
                                    if black_key == "ip" and (format_tools.pattern_matching(line[header.index("src")], black_dict[black_key])
                                                              or format_tools.pattern_matching(line[header.index("dst")], black_dict[black_key])):
                                        is_black = True
                                    elif black_key == "full_feature" and format_tools.pattern_matching(cur_line_feature, black_dict[black_key]):
                                        is_black = True
                                    elif black_key in header and format_tools.pattern_matching(line[header.index(black_key)], black_dict[black_key]):
                                        is_black = True
                                    if is_black:
                                        feature_filter_by_general_list.append(cur_line_feature)
                                        break

                                # check if current protocol should be filtered
                                if is_black or (line[header.index("protocol")] not in protocol_to_be_filtered) or (cur_line_feature in feature_filter_by_general_list):
                                    continue

                                if cur_line_feature not in feature_ops_dict:
                                    feature_ops_dict[cur_line_feature] = [full_action_name]
                                elif full_action_name not in feature_ops_dict[cur_line_feature]:
                                    feature_ops_dict[cur_line_feature].append(full_action_name)

        # static
        feature_ops_dict = format_tools.sort_dict_by_key(feature_ops_dict)
        with open(dataset_path + FEATURE_STATIC_JSON, "w") as f:
            f.write(json.dumps(feature_ops_dict, indent=4))

        for feature in feature_ops_dict:
            with open(f"{ROOT_PATH}/white_list.json", "r") as white_file:
                white_dict = json.load(white_file)

            is_white = False
            for field in white_dict.keys():
                if is_white:
                    break
                for white_item in white_dict[field]:
                    if white_item.replace("mustsel-", "") in feature:
                        is_white = True
                        break

            if not is_white and len(feature_ops_dict[feature]) > threshold_among_each_kind_of_action * count_of_op:
                feature_filter_by_general_list.append(feature)

        feature_filter_by_general_list = format_tools.deduplicate_for_list(feature_filter_by_general_list)
        feature_filter_by_general_list.sort()

        # record feature in black list
        with open(dataset_path + FILTERED_FEATURE_TXT, "w") as f:
            for feature in feature_filter_by_general_list:
                f.write(feature)
                f.write("\n")

        """
            ================================ module 3 ================================
            Select the action that occurs more than threshold(half) in one action
        """
        mlog.log_func(mlog.LOG, "Start module 3: selecting the action that occurs more than the threshold in one action.")

        # construct: {action: {click_item: {feature: [payload_list]}}}
        features_occur_for_each_time_dict = {}  # It is used to count the pattern corresponding to each feature when each click is executed under each action

        # get feature aggregation from each csv and static appearance time
        for distance_folder in all_packet_folder_list:
            if not os.path.isdir(dataset_path + distance_folder):
                continue
            if distance_folder not in features_occur_for_each_time_dict.keys():
                features_occur_for_each_time_dict[distance_folder] = {}
            distance_folder_path = dataset_path + distance_folder + "/"
            under_distance_files = os.listdir(distance_folder_path)

            for user_pcap_txt in under_distance_files:
                if not os.path.isdir(distance_folder_path + user_pcap_txt):
                    continue
                if user_pcap_txt not in features_occur_for_each_time_dict[distance_folder]:
                    features_occur_for_each_time_dict[distance_folder][user_pcap_txt] = {}
                user_folder_path = distance_folder_path + user_pcap_txt + "/"
                action_folders = os.listdir(user_folder_path)

                for action in action_folders:
                    action_folder = user_folder_path + action + "/"
                    if not os.path.isdir(action_folder):
                        continue

                    fea_times_in_cur_op_dict = {}

                    if action not in features_occur_for_each_time_dict[distance_folder][user_pcap_txt]:
                        features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action] = dict()

                    # for item in os.listdir(action_folder):
                    for item in [x for x in os.listdir(action_folder) if x.split(".")[-1] == "csv"]:
                        cur_action_item = "_".join(item.split("_")[:-1]).split("|")[-1]
                        # add action_timestamp to dict
                        if cur_action_item not in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action]:
                            features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][cur_action_item] = {}

                        # read csv file and get appear time for each feature
                        with open(action_folder + item, "r") as file:
                            reader = csv.reader(file)
                            header = next(reader)
                            for line in list(reader):
                                cur_line_feature = "|".join(line[header.index("domain"):])

                                # check if current line feature is filtered
                                if cur_line_feature in feature_filter_by_general_list:# or line[protocol_index] not in protocol_to_be_filtered:
                                    continue

                                # Add feature to the dictionary which will be used later to add payload
                                if cur_line_feature not in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][cur_action_item]:
                                    features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][cur_action_item][cur_line_feature] = []

                                # Add to the dictionary of counts
                                if cur_line_feature not in fea_times_in_cur_op_dict:
                                    fea_times_in_cur_op_dict[cur_line_feature] = []
                                if f'{user_pcap_txt}|{distance_folder}|{cur_action_item}' not in fea_times_in_cur_op_dict[cur_line_feature]:
                                    fea_times_in_cur_op_dict[cur_line_feature].append(f'{user_pcap_txt}|{distance_folder}|{cur_action_item}')

                    with open(action_folder + FEATURE_STATIC_JSON, "w") as f:
                        f.write(json.dumps(fea_times_in_cur_op_dict, indent=4))

                    filtered_file_handle = open(action_folder + FILTERED_FEATURE_TXT, "w")
                    selected_file_handle = open(action_folder + SELECTED_FEATURE_TXT, "w")
                    # cur_action_threshold = threshold_in_one_op * total_op_pcap
                    cur_action_threshold = threshold_in_one_op * len([x for x in os.listdir(action_folder) if x.split(".")[-1] == "txt" and action in x])
                    for feature in fea_times_in_cur_op_dict:
                        with open(f"{ROOT_PATH}/white_list.json", "r") as white_file:
                            white_dict = json.load(white_file)

                        is_white = False
                        for field in white_dict.keys():
                            if is_white:
                                break
                            for white_item in white_dict[field]:
                                if "mustsel-" not in white_item:
                                    continue
                                if white_item[len("mustsel-"):] in feature:
                                    is_white = True
                                    break

                        filtered_file_handle.write(f"{feature}\n") if not is_white and len(fea_times_in_cur_op_dict[feature]) < cur_action_threshold else selected_file_handle.write(f"{feature}\n")
                    filtered_file_handle.close()
                    selected_file_handle.close()

        """
                ================================ module 3.5 ================================
                    check remote folders
        """

        # create empty csv file and get file size
        # save_feature_in_csv_file([], f"{ROOT_PATH}/empty.csv")
        # empty_size = os.path.getsize(f"{ROOT_PATH}/empty.csv")
        # os.remove(f"{ROOT_PATH}/empty.csv")

        for distance in all_packet_folder_list:
            if distance != "remote" or not os.path.isdir(dataset_path + distance):
                continue

            distance_folder_path = dataset_path + distance + "/"
            under_distance_files = os.listdir(distance_folder_path)
            for user in under_distance_files:
                if not os.path.isdir(distance_folder_path + user):
                    continue

                user_folder_path = distance_folder_path + user + "/"
                action_folders = os.listdir(user_folder_path)
                for action in action_folders:
                    action_folder = user_folder_path + action + "/"
                    if not os.path.isdir(action_folder):
                        continue

                    cur_op_selected_features = []
                    with open(action_folder + SELECTED_FEATURE_TXT, "r") as sel_file_handle:
                        lines = sel_file_handle.readlines()
                        for line in lines:
                            if line:
                                cur_op_selected_features.append(line.replace("\n", ""))

                    action_files = os.listdir(action_folder)
                    if os.path.exists(f"{action_folder}/need_read_local"):
                        os.remove(f"{action_folder}/need_read_local")

                    need_read_local_flag = False
                    for file in action_files:
                        if need_read_local_flag:
                            break
                        if "_local" not in file or action not in file:
                            continue
                        file_path = action_folder + file
                        with open(file_path, "r") as csv_file_handle:
                            reader = csv.reader(csv_file_handle)
                            header = next(reader)
                            lines = list(reader)
                            for line in lines:
                                cur_line_feature = "|".join(line[header.index("domain"):])
                                if cur_line_feature in cur_op_selected_features:
                                    need_read_local_flag = True
                                    break

                    if need_read_local_flag:
                        os.mknod(f"{action_folder}/need_read_local")

        """
                ================================ module 4 ================================
                    get payload and payload pattern
        """
        mlog.log_func(mlog.LOG, "Start module 4: get payload from dataset and extract payload pattern")

        # get feature aggregation from each csv and static appearance time
        op_feature_pattern_dict = {}
        for distance_folder in all_packet_folder_list:
            if not os.path.isdir(dataset_path + distance_folder):
                continue
            distance_folder_path = dataset_path + distance_folder + "/"
            if distance_folder not in op_feature_pattern_dict:
                op_feature_pattern_dict[distance_folder] = dict()

            for user_pcap_txt in [x for x in os.listdir(distance_folder_path) if os.path.isdir(distance_folder_path + x)]:
                if user_pcap_txt not in op_feature_pattern_dict[distance_folder]:
                    op_feature_pattern_dict[distance_folder][user_pcap_txt] = dict()

                user_folder_path = distance_folder_path + user_pcap_txt + "/"
                action_folders = os.listdir(user_folder_path)
                for action in action_folders:
                    action_folder = user_folder_path + action + "/"
                    if not os.path.isdir(action_folder):
                        continue

                    # if f"{user_pcap_txt}|{distance_folder}|{action}" != "user1|remote|DeviceControl":
                    #     continue

                    mlog.log_func(mlog.LOG, f"Current action: {user_pcap_txt}|{distance_folder}|{action}", t_count=1)

                    # read selected txt and get selected features
                    cur_op_selected_features = []
                    with open(action_folder + SELECTED_FEATURE_TXT, "r") as sel_file_handle:
                        lines = sel_file_handle.readlines()
                        for line in lines:
                            if line:
                                cur_op_selected_features.append(line.replace("\n", ""))

                    feature_payloads_dict = {}
                    for op_files in [x for x in os.listdir(action_folder) if x.split('.')[-1] == 'txt' and action in x]:
                        # get pcap name, filter condition from txt
                        pcap_files = {}
                        with open(action_folder + op_files, "r") as f:
                            txt_line = f.readlines()
                            filter_condition = txt_line[-1].replace("\n", "")
                            pcap_file_name = txt_line[0].replace("\n", "")
                            key_file_name = pcap_file_name.split(".")[0] + ".txt"
                            pcap_files[distance_folder] = [distance_folder_path + pcap_file_name, distance_folder_path + key_file_name, filter_condition]

                            # if current packet is remote, get local pcapng file path and filter condition
                            if distance_folder == "remote" and os.path.exists(f"{action_folder}/need_read_local"):
                                local_pcap = "_".join(pcap_file_name.split("_")[:-1]) + "_local.pcapng"
                                local_key = "_".join(key_file_name.split("_")[:-1]) + "_local.txt"
                                local_filter = format_tools.get_merged_wireshark_filter_expression([
                                    format_tools.get_wireshark_filter_by_timestamp(txt_line[1].replace("\n", ""),
                                                                                   txt_line[2].replace("\n", "")),
                                    format_tools.get_wireshark_filter_expression_by_selected_ip_list(
                                        phone_device_ip_dict["devices"]),
                                    protocol_filter_expression
                                ])
                                pcap_files["local"] = [dataset_path + "local/" + local_pcap, dataset_path + "local/" + local_key, local_filter]
                            elif distance_folder == "local" and os.path.exists(f"{action_folder}/{op_files.split('|')[-1].split('.')[0]}"):
                                direct_pcap = f"{action_folder}/{op_files.split('|')[-1].split('.')[0]}"
                                direct_filter = protocol_filter_expression
                                pcap_files["direct"] = [direct_pcap, distance_folder_path + key_file_name, direct_filter]

                        # get selected packet number
                        selected_numbers_feature = {}
                        cur_op_csv_files = [
                            op_files.split(".")[0] + "_remote.csv",
                            op_files.split(".")[0] + "_local.csv",
                            op_files.split('|')[-1].split('.')[0] + "_direct.csv"
                        ]

                        # read csv file and get selected number:feature
                        for csv_file in cur_op_csv_files:
                            if not os.path.exists(action_folder + csv_file):
                                continue

                            # add distance to selected_number_feature
                            cur_csv_distance = csv_file.split("_")[-1].split(".")[0]
                            selected_numbers_feature[cur_csv_distance] = {}

                            # get selected numbers
                            with open(action_folder + csv_file, "r") as f:
                                reader = csv.reader(f)
                                header = next(reader)
                                lines = list(reader)
                                for line in lines:
                                    cur_line_feature = "|".join(line[header.index("domain"):])
                                    # if current line is not select, next one
                                    if not format_tools.pattern_matching(cur_line_feature, cur_op_selected_features):
                                        continue

                                    # if current line has response number and the source is phone
                                    if line[header.index("response_number")]:
                                        if line[header.index("src")] in phone_ip_list:
                                            # add response number
                                            selected_numbers_feature[cur_csv_distance][line[header.index("response_number")]] = cur_line_feature
                                    else:
                                        if line[header.index("dst")] in phone_device_ip_list:
                                            selected_numbers_feature[cur_csv_distance][line[header.index("number")]] = cur_line_feature

                        # read pcap file and get payload
                        for dist_index in pcap_files:
                            # if nothing, continue
                            if not len(list(selected_numbers_feature[dist_index].keys())):
                                continue

                            pcap = pyshark.FileCapture(pcap_files[dist_index][0], display_filter=pcap_files[dist_index][-1], use_json=True,
                                                       override_prefs={'ssl.keylog_file': pcap_files[dist_index][1]})
                            for packet in pcap:
                                str_number = str(packet.number)
                                if str_number in selected_numbers_feature[dist_index]:
                                    if selected_numbers_feature[dist_index][str_number] not in feature_payloads_dict:
                                        feature_payloads_dict[selected_numbers_feature[dist_index][str_number]] = []
                                    # get payload
                                    payload = get_payload_from_packet(packet)
                                    feature_payloads_dict[selected_numbers_feature[dist_index][str_number]].append(payload)
                                    features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][op_files.split(".")[0].split('|')[-1]][selected_numbers_feature[dist_index][str_number]].append(payload)
                            pcap.close()

                    """
                    [to do]
                    """
                    # get patterns for payload split by length
                    feature_payloads_pattern = {}
                    for key in feature_payloads_dict:
                        feature_payloads_dict[key] = split_list_by_length(feature_payloads_dict[key])
                        if key not in feature_payloads_pattern:
                            feature_payloads_pattern[key] = []
                        for len_split_payloads in feature_payloads_dict[key]:
                            feature_payloads_pattern[key].append(
                                format_tools.get_patterns_for_cases(len_split_payloads.copy(), not format_tools.is_raw_data(key)))

                    op_feature_pattern_dict[distance_folder][user_pcap_txt][action] = feature_payloads_pattern

                    with open(f"{action_folder}/{PAYLOAD_STATIC_JSON}", "w") as f:
                        f.write(json.dumps(feature_payloads_dict, indent=4))

                    with open(f"{action_folder}/{PAYLOAD_PATTERN_JSON}", "w") as f:
                        f.write(json.dumps(feature_payloads_pattern, indent=4))


        """
            ================================ module 5 ================================
            get abstract class for each class of pattern
        """
        mlog.log_func(mlog.LOG, "Start module 5: Classify")
        for distance_folder in all_packet_folder_list:
            if not os.path.isdir(dataset_path + distance_folder):
                continue
            distance_folder_path = dataset_path + distance_folder + "/"
            under_distance_files = os.listdir(distance_folder_path)

            for user_pcap_txt in under_distance_files:
                if not os.path.isdir(distance_folder_path + user_pcap_txt):
                    continue
                user_folder_path = distance_folder_path + user_pcap_txt + "/"
                action_folders = os.listdir(user_folder_path)

                for action in action_folders:
                    if not os.path.isdir(user_folder_path + action):
                        continue

                    for click_item in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action]:
                        for feature in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item]:
                            # if current feature is not in pattern, continue
                            if feature not in op_feature_pattern_dict[distance_folder][user_pcap_txt][action]:
                                continue
                            for index in range(len(features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature])):
                                # use pattern of each length to match
                                for each_len_patterns_list in op_feature_pattern_dict[distance_folder][user_pcap_txt][action][feature]:
                                    matched_pattern = format_tools.pattern_matching(
                                        features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature][index],
                                        each_len_patterns_list,
                                        format_tools.is_raw_data(feature))
                                    if matched_pattern:
                                        features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature][index] = "".join(matched_pattern)
                                        break
                            features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature] = format_tools.deduplicate_for_list(features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature])

                # get class
                classify_dict = {}
                for action in features_occur_for_each_time_dict[distance_folder][user_pcap_txt].keys():
                    mlog.log_func(mlog.LOG, f"Current action: {user_pcap_txt}|{distance_folder}|{action}", t_count=1)

                    if action not in classify_dict:
                        classify_dict[action] = []
                    for click_item in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action]:
                        temp_list = []
                        # Concatenate feature and pattern into a long string split by FPSPER
                        for feature in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item]:
                            for pattern_str in features_occur_for_each_time_dict[distance_folder][user_pcap_txt][action][click_item][feature]:
                                fp_str = feature + "FPSPER" + pattern_str
                                temp_list.append(fp_str)
                        temp_list = sorted(format_tools.deduplicate_for_list(temp_list))
                        classify_dict[action].append("CLSSPER".join(temp_list))

                    classify_dict[action] = format_tools.deduplicate_for_list(classify_dict[action])

                    # split
                    for i in range(len(classify_dict[action])-1, -1, -1):
                        classify_dict[action][i] = classify_dict[action][i].split("CLSSPER")

                    classify_dict[action] = sorted(classify_dict[action], key=lambda x: len(x), reverse=True)
                    # check subset
                    for i in range(len(classify_dict[action])-1, -1, -1):
                        for j in range(i-1, -1, -1):
                            if set(classify_dict[action][i]) <= set(classify_dict[action][j]):
                                classify_dict[action].pop(i)
                                break

                    # save
                    with open(f"{user_folder_path}{action}/{CLASSIFY_RESULT_JSON}", "w") as f:
                        f.write(json.dumps(classify_dict[action], indent=4))



def get_new_op_class_for_response(database, new_pcapng_file_path, keylog_file_path, op_name, action_start_time, action_end_time, use_manual_ip=False):
    """
    Giving a new pcapng file of an action, get it's abstract class
    :param new_pcapng_file_path: PATH to pcapng file, such as "/path/to/SA_111.pcapng"
    :param keylog_file_path: PATH to decrypted file, corresponding to the pcapng file
    :param op_name: current action full name, such as "user1|local|AddDevice"
    :param action_start_time: start timestamp of op_name
    :param action_end_time: end timestamp of op_name
    :return: abstract class for response -> str
    """
    mlog.log_func(mlog.LOG, f"Parse and get new response for action: <{op_name}>")

    if not os.path.exists(new_pcapng_file_path) or not os.path.exists(keylog_file_path):
        mlog.log_func(mlog.ERROR, f"pcapng or keylog file path ERROR! Please check.")
        return None

    # return the same class for special response
    if specific_response_flag and op_name in specific_response_op_name_list:
        mlog.log_func(mlog.DEBUG, "Response by manual select")
        return f"{op_name}_CLS_{specific_response_op_name_list[op_name]}"

    """ 
        get knowledge from database
    """

    # Concatenate the path of the database
    database_root_path = PACKET_ROOT_PATH + database + "/"
    op_root_path = f'{database_root_path}{op_name.split("|")[1]}/{op_name.split("|")[0]}/{op_name.split("|")[-1]}/'

    # get selected features from database(use payload pattern features)
    with open(op_root_path + PAYLOAD_PATTERN_JSON, "r") as f:
        selected_features_list = list(json.load(f).keys())

    # Convert selected_features
    for index in range(len(selected_features_list)):
        selected_features_list[index] = format_tools.split_feature_str_to_pattern_list(selected_features_list[index])

    # get the knowledge of dns mapping from ip to domain
    dns_mapping = get_dns_result()

    # get black name list
    with open(ROOT_PATH + "/black_list.json", "r") as bf:
        black_dict = json.load(bf)

    # get phone and device ip
    try:
        pd_dict = get_user_distance_and_device_ip_list(["|".join(op_name.split("|")[:-1])], use_manual_ip)
    except Exception as e:
        mlog.log_func(mlog.ERROR, e)
        return None

    """ 
        read pcap file 
        get header features and payload
    """

    # get white ip list
    merged_ip_list = get_ips.merge_manual_ip_list(pd_dict[:-1], database)

    # generate filter expression of current action
    new_op_filter_expression = format_tools.get_merged_wireshark_filter_expression([
                                format_tools.get_wireshark_filter_by_timestamp(action_start_time, action_end_time),
                                protocol_filter_expression,
                                format_tools.get_wireshark_filter_expression_by_blackname_list_dict(black_dict),
                                format_tools.get_wireshark_filter_expression_by_selected_ip_list(pd_dict),
                                format_tools.get_wireshark_filter_expression_by_selected_ip_list(merged_ip_list)
                            ])

    new_op_root_path = f'{"/".join(new_pcapng_file_path.split("/")[:-1])}/{op_name.split("|")[0]}/{op_name.split("|")[-1]}/'
    # record filter expression in file
    with open(f'{new_op_root_path}/{op_name}_{int(action_start_time)}.txt', "w") as op_st_f:
        op_st_f.write(f"{new_pcapng_file_path.split('/')[-1]}\n{action_start_time}\n{action_end_time}\n{new_op_filter_expression}")

    # save header features in this dict
    save_header_feature_dict = {}  # {local: header_features}
    pcap_and_keylog_dict = {}
    distance_payload_dict = {}

    while True:
        # read pcapng file and get header features
        pcap = pyshark.FileCapture(new_pcapng_file_path, display_filter=new_op_filter_expression,
                                   override_prefs={'ssl.keylog_file': keylog_file_path})
        new_op_header_features_dict_list, dns_update_flag, number_payload_dict = get_header_features(pcap, new_pcapng_file_path, dns_mapping, use_old_ip_version=use_manual_ip)
        try:
            pcap.close()
        except Exception:
            pass

        if new_op_header_features_dict_list != -1 and dns_update_flag != -1:
            break
        else:
            mlog.log_func(mlog.ERROR, "Tshark maybe crash, sleep and re-start")
            time.sleep(0.5)
    # update dns
    if dns_update_flag:
        dns_mapping = get_dns_result()

    save_header_feature_dict[op_name.split("|")[1]] = new_op_header_features_dict_list
    pcap_and_keylog_dict[op_name.split("|")[1]] = [new_pcapng_file_path, keylog_file_path]
    distance_payload_dict[op_name.split("|")[1]] = number_payload_dict

    # if current distance is remote, check local pcap too
    if op_name.split("|")[1] == "remote" and os.path.exists(f"{op_root_path}/need_read_local"):
        mlog.log_func(mlog.DEBUG, f"Current distance is remote, read local pcapng...")

        # get local pcapng file name
        corresponding_local_pcap_path = "/".join(new_pcapng_file_path.split("/")[:-2]) + "/local/" + "_".join(new_pcapng_file_path.split("/")[-1].split("_")[:-1]) + "_local.pcapng"
        corresponding_local_key_file_path = corresponding_local_pcap_path[:-6] + "txt" if "sslkeylogfile" not in keylog_file_path else "_".join(keylog_file_path.split("_")[:-1]) + "_local.txt"
        local_filter_expression = format_tools.get_wireshark_filter_by_timestamp(action_start_time, action_end_time) + " and " + format_tools.get_wireshark_filter_expression_by_selected_ip_list(get_phone_and_device_ip(use_manual_ip)["devices"])

        while True:
            # read file and get features
            pcap = pyshark.FileCapture(corresponding_local_pcap_path, display_filter=local_filter_expression,
                                       override_prefs={'ssl.keylog_file': corresponding_local_key_file_path})
            local_header_features_dict_list, dns_update_flag, local_number_payload_dict = get_header_features(pcap,
                                                                                   corresponding_local_pcap_path,
                                                                                   dns_mapping, use_old_ip_version=use_manual_ip)
            try:
                pcap.close()
            except Exception:
                pass

            if local_header_features_dict_list != -1 and dns_update_flag != -1:
                break
            else:
                mlog.log_func(mlog.ERROR, "Tshark maybe crash, sleep and re-start")
                time.sleep(0.5)
        # save in dicts
        save_header_feature_dict["local"] = local_header_features_dict_list
        pcap_and_keylog_dict["local"] = [corresponding_local_pcap_path, corresponding_local_key_file_path]
        distance_payload_dict["local"] = local_number_payload_dict
    elif op_name.split("|")[1] == "local" and os.path.exists(f"{new_op_root_path}/{op_name.split('|')[-1]}_{int(action_start_time)}"):
        mlog.log_func(mlog.DEBUG, f"Read tcpdump result...")

        tcpdump_filter_exp = format_tools.get_merged_wireshark_filter_expression([
            # format_tools.get_wireshark_filter_by_timestamp(action_start_time, action_end_time),
            protocol_filter_expression
        ])
        direct_pcap_path = f"{new_op_root_path}/{op_name.split('|')[-1]}_{int(action_start_time)}"
        pcap = pyshark.FileCapture(direct_pcap_path, display_filter=tcpdump_filter_exp)
        save_header_feature_dict["direct"], dns_update_flag, distance_payload_dict["direct"] = get_header_features(pcap, direct_pcap_path, dns_mapping, use_old_ip_version=use_manual_ip)
        pcap_and_keylog_dict["direct"] = [direct_pcap_path, direct_pcap_path]
        pcap.close()

    # check
    null_flag = True
    for key in save_header_feature_dict:
        if save_header_feature_dict[key]:
            null_flag = False
    if null_flag:
        mlog.log_func(mlog.DEBUG, "Can not extract any header features from pcap, please check ip(filter condition) or other")
        return f"{op_name}_CLS_NoResp"

    """
        keep selected features
    """

    # sort dict unit by list
    sorted_distance_header_dict = {}
    distance_new_feature_index_dict = {}
    distance_number_to_be_read_dict = {}
    start_index = fieldnames_of_csv.index("domain")

    # start sort and get numbers to be read(selected)
    for distance in save_header_feature_dict.keys():
        sorted_distance_header_dict[distance] = []
        distance_new_feature_index_dict[distance] = []
        distance_number_to_be_read_dict[distance] = []
        for ori_dict_index in range(len(save_header_feature_dict[distance])):
            ori_dict = save_header_feature_dict[distance][ori_dict_index]
            sorted_header_feature_dict = OrderedDict()

            # sort by name
            for key in fieldnames_of_csv:
                sorted_header_feature_dict[key] = ori_dict.get(key) if ori_dict.get(key) else ""

            # check if this line is in selected lines
            current_line_str = "|".join(list(sorted_header_feature_dict.values())[start_index:])
            if not format_tools.pattern_matching(current_line_str, selected_features_list):
                continue

            # add to feature list for analyse
            sorted_distance_header_dict[distance].append(sorted_header_feature_dict)

            if sorted_header_feature_dict["dst"] in pd_dict:
                # get packet number in pcapng file
                distance_number_to_be_read_dict[distance].append(sorted_header_feature_dict["number"])

    """
        read payload patterns and classify results from dataset
        get payloads generated by new action
    """

    # get payload patterns from database
    with open(f"{op_root_path}/{PAYLOAD_PATTERN_JSON}", "r") as payload_file:
        payload_pattern_dict = json.load(payload_file)
    payload_pattern_features = list(payload_pattern_dict.keys())  # split feature-> pattern
    for feature_index in range(len(payload_pattern_features)):
        payload_pattern_features[feature_index] = format_tools.split_feature_str_to_pattern_list(payload_pattern_features[feature_index])

    # get classify result from database
    database_classify_file_path = f"{database_root_path}/{op_name.split('|')[1]}/{op_name.split('|')[0]}/{op_name.split('|')[2]}/{CLASSIFY_RESULT_JSON}"
    with open(database_classify_file_path, "r") as f:
        database_classify_result = json.load(f)

    # get payloads of this new action
    distance_packet_number_payload_dict = dict()
    for distance in pcap_and_keylog_dict.keys():
        distance_packet_number_payload_dict[distance] = {}
        for str_number in distance_number_to_be_read_dict[distance]:
            distance_packet_number_payload_dict[distance][str_number] = distance_payload_dict[distance][str_number]

    """
        get classify result of new action
    """

    temp_feature_payload_combine_list = []  # "featureFPSPERpayload" list
    not_match_index_list = []

    for distance in sorted_distance_header_dict:
        sorted_header_feature_list = sorted_distance_header_dict[distance]
        # use patterns to match payload
        for item_index in range(len(sorted_header_feature_list)):
            item = sorted_header_feature_list[item_index]

            # jump if (protocol is http and doesn't have response) or (does not have payload)
            if item["number"] not in distance_packet_number_payload_dict[distance]:
                continue

            # get the corresponding pattern of this line str
            current_line_str = "|".join(list(item.values())[start_index:])
            matching_result = format_tools.pattern_matching(current_line_str, payload_pattern_features)
            if matching_result:
                current_line_str = "".join(matching_result)
            else:
                mlog.log_func(mlog.DEBUG, f"Line str {current_line_str} is not in pattern database, ignore it and continue")
                continue

            current_feature_patterns = payload_pattern_dict[current_line_str]
            # Read the payload from the dictionary read earlier
            current_payload = distance_packet_number_payload_dict[distance][item["response_number"] if item["response_number"] and item["response_number"] in distance_packet_number_payload_dict[distance] else item["number"]]
            # Match the pattern of each length
            for each_len_patterns in current_feature_patterns:
                matching_result = format_tools.pattern_matching(current_payload, each_len_patterns, format_tools.is_raw_data(current_line_str))
                if matching_result:
                    current_payload = "".join(matching_result)
                    break
            # add to combine list for classify
            if f"{current_line_str}FPSPER{current_payload}" not in temp_feature_payload_combine_list:
                temp_feature_payload_combine_list.append(f"{current_line_str}FPSPER{current_payload}")
                # record the payload which does not match
                if not matching_result:
                    not_match_index_list.append(len(temp_feature_payload_combine_list)-1)

    if not temp_feature_payload_combine_list:
        mlog.log_func(mlog.ERROR, "Does not extract anything, please check your filter expression")
        return f"{op_name}_CLS_NoResp"
        # return f"NoElement"

    # if not in exist classes
    if not_match_index_list:
        mlog.log_func(mlog.LOG, "Some payload doesn't have match pattern")

        # If the current category not exists
        not_match_dict = {}
        # add not match payload
        for not_match_payload_index in not_match_index_list:
            cur_feature = temp_feature_payload_combine_list[not_match_payload_index].split("FPSPER")[0]
            cur_payload = temp_feature_payload_combine_list[not_match_payload_index].split("FPSPER")[-1]
            mlog.log_func(mlog.DEBUG, f"{cur_feature}\n{cur_payload}")
            mlog.log_func(mlog.DEBUG, "-------------split line-------------")

            if cur_feature not in not_match_dict:
                not_match_dict[cur_feature] = []
            not_match_dict[cur_feature].append(cur_payload)

        # load payload static
        with open(f"{database_root_path}/{op_name.split('|')[1]}/{op_name.split('|')[0]}/{op_name.split('|')[2]}/{PAYLOAD_STATIC_JSON}", "r") as static_file:
            payload_static_dict = json.load(static_file)

        # merge
        for cur_feature in not_match_dict:
            static_payload_list = payload_static_dict[cur_feature]
            total_payload_list = []

            # merge each length from database
            for each_len_payload in static_payload_list:
                total_payload_list.extend(each_len_payload)

            # merge new payload
            total_payload_list.extend(not_match_dict[cur_feature])

            # split by length
            payload_static_dict[cur_feature] = split_list_by_length(total_payload_list)

            # get pattern for merged payload
            new_pattern_list = []
            for static_index in range(len(payload_static_dict[cur_feature])):
                # payload_pattern_dict[cur_feature][static_index] = format_tools.get_patterns_for_cases(payload_static_dict[cur_feature][static_index].copy(), not format_tools.is_raw_data(cur_feature))
                new_pattern_list.append(
                    format_tools.get_patterns_for_cases(payload_static_dict[cur_feature][static_index].copy(), not format_tools.is_raw_data(cur_feature)))
            payload_pattern_dict[cur_feature] = new_pattern_list

        # add to payload static file
        with open(f'{database_root_path}/{op_name.split("|")[1]}/{op_name.split("|")[0]}/{op_name.split("|")[-1]}/{PAYLOAD_STATIC_JSON}', "w") as static_file:
            static_file.write(json.dumps(payload_static_dict, indent=4))

        # add to payload pattern file
        with open(f'{database_root_path}/{op_name.split("|")[1]}/{op_name.split("|")[0]}/{op_name.split("|")[-1]}/{PAYLOAD_PATTERN_JSON}', "w") as payload_file:
            payload_file.write(json.dumps(payload_pattern_dict, indent=4))
    else:
        # set and sorted
        temp_feature_payload_combine_list_sorted = sorted(temp_feature_payload_combine_list)

        # Compare with what has already been classified
        temp_feature_payload_combine_cls = "CLSSPER".join(temp_feature_payload_combine_list_sorted)
        for result_index in range(len(database_classify_result)):
            if temp_feature_payload_combine_cls == "CLSSPER".join(database_classify_result[result_index]):
                # If the current category exists, return result
                mlog.log_func(mlog.LOG, "Congratulations! Category exists")
                return f"{op_name}_CLS_{result_index}"

        # check subset
        for result_index in range(len(database_classify_result)):
            for subset_item in temp_feature_payload_combine_cls.split("CLSSPER"):
                print(subset_item)
            is_subset = True
            for payload_line in temp_feature_payload_combine_list_sorted:
                if payload_line not in database_classify_result[result_index]:
                    is_subset = False
                    break
            if is_subset:
                mlog.log_func(mlog.LOG, "Subset of existed class")
                return f"{op_name}_CLS_{result_index}"

    mlog.log_func(mlog.LOG, "All payload match, but not in recent classify result")

    # get new classify result
    for not_match_payload_index in not_match_index_list:
        feature_fpsper_payload = temp_feature_payload_combine_list[not_match_payload_index]
        cur_feature = feature_fpsper_payload.split("FPSPER")[0]
        cur_payload = feature_fpsper_payload.split("FPSPER")[1]

        # use new pattern to match
        for each_len_patterns in payload_pattern_dict[cur_feature]:
            matching_result = format_tools.pattern_matching(cur_payload, each_len_patterns, format_tools.is_raw_data(cur_feature))
            if matching_result:
                cur_payload = "".join(matching_result)
                break

        temp_feature_payload_combine_list[not_match_payload_index] = cur_feature + "FPSPER" + cur_payload

    mlog.log_func(mlog.LOG, "Find new class!!!")
    # set and sorted
    temp_feature_payload_combine_list = sorted(format_tools.deduplicate_for_list(temp_feature_payload_combine_list))

    # add to classify result
    database_classify_result.append(temp_feature_payload_combine_list)

    # # write to file
    with open(database_classify_file_path, "w") as classify_file:
        classify_file.write(json.dumps(database_classify_result, indent=4))

    # return new classify result
    return f"{op_name}_CLS_{len(database_classify_result)-1}"

