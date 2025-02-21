import sys
import re
from cmd import Cmd
import queue
import yaml
import pprint as pp

from typing import Literal, Optional
from AS_class import AS_class_list, AS_class

OUTSIDE_AS = 64512

class LOTUSInputError(Exception):
    pass

class LOTUS():
    def __init__(self):
        self.as_class_list = AS_class_list()
        self.message_queue = queue.Queue()
        self.connection_list = []
        self.public_aspa_list = {}

    def addAS(self, asn:str) -> int:
        # TODO: Consider the case the given asn has already exist.
        assert isinstance(asn, str)
        self.as_class_list.add_AS(asn)

    def showAS(self, asn:str) -> list[int]:
        assert isinstance(asn, str)
        try:
            self.as_class_list.get_AS(asn).show_info()
        except:
            print(f"Error: AS {asn} is NOT registerd.")

    def getAS(self, asn:str) -> Optional[AS_class]:
        assert isinstance(asn, str) and asn.isdecimal()
        try:
            return self.as_class_list.get_AS(asn)
        except KeyError:
            return None

    def showASList(self, address:Optional[str] = None, sort_flag:bool = False, best_flag:bool = False) -> None:
        assert isinstance(address, Optional[str])
        assert (address == "") or (address is None) or (re.fullmatch("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/[0-9][0-9]" , address))
        self.as_class_list.show_AS_list(sort_flag, best_flag, address)

    def addMessage(self, type:Literal["init", "update"], params:dict) -> None:
        if type == "init":
            assert params.keys() == ["src"]
            assert isinstance(params["src"], str) and params["src"].isdecimal()
            self.message_queue.put({"type": "init", "src": params["src"]})
        elif type == "update":
            assert params.keys() == ["src", "dst", "path", "network"]
            assert isinstance(params["src"], str) and params["src"].isdecimal()
            assert isinstance(params["dst"], str) and params["dst"].isdecimal()
            assert re.fullmatch("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/[0-9][0-9]", params["network"])
            self.message_queue.put({"type": "update", "src": params["src"], "dst":params["dst"], "path":params["path"], "network":params["network"]})
        else:
            assert False, "type is invalid."

    def addAllASInit(self) -> None:
        for asn in self.as_class_list.get_AS_list().keys():
            self.message_queue.put({"type": "init", "src": asn})

    def showMessage(self) -> None:
        tmp_queue = queue.Queue()
        while not self.message_queue.empty():
            q = self.message_queue.get()
            print(q)
            tmp_queue.put(q)
        self.message_queue = tmp_queue

    def addConnection(self, type:Literal["peer", "down"], src_asn:str, dst_asn:str) -> None:
        assert isinstance(src_asn, int)
        assert isinstance(dst_asn, int)
        assert type in ["peer", "down"]
        if type == "peer":
            self.connection_list.append({"type": "peer", "src": src_asn, "dst": dst_asn})
        elif type == "down":
            self.connection_list.append({"type": "down", "src": src_asn, "dst": dst_asn})

    def showConnection(self):
        # TODO: filtering
        for c in self.connection_list:
            pp.pprint(c)

    def addASPA(self, customer_asn:str, provider_asns:list[int]) -> None:
        assert customer_asn.isdecimal()
        assert isinstance(provider_asns, list) and all(i.isdecimal() for i in provider_asns)
        # TODO: customer_asnに既にASPAが存在する時の処理(今は上書きしているけど追加 and/or 修正できる？)
        self.public_aspa_list[customer_asn] = provider_asns

    def showASPA(self, customer_asn:Optional[int] = None) -> None:
        if customer_asn is None:
            pp.pprint(self.public_aspa_list)
        else:
            pp.pprint(self.public_aspa_list[customer_asn])

    def getASPA(self, customer_asn:Optional[int] = None) -> dict:
        if customer_asn is None:
            return self.public_aspa_list
        else:
            return self.public_aspa_list[customer_asn]

    def setASPV(self, asn:str, switch:Literal["on", "off"], priority:Optional[str]=None) -> None:
        assert isinstance(asn, str)
        assert switch in ["on", "off"]
        if switch == "on":
            assert priority in ["1", "2", "3"]
        as_class = self.as_class_list.get_AS(asn)
        if switch == "on":
            as_class.change_ASPV({"switch": "on", "priority": priority})
        elif switch == "off":
            as_class.change_ASPV({"switch": "off"})

    def get_connection_with(self, as_number:str):
        assert isinstance(as_number, str)
        c_list = []
        for c in self.connection_list:
            if as_number in [c["src"], c["dst"]]:
                c_list.append(c)
        return c_list

    def get_adjacent_as(self, asn:str, provider:bool=False, customer:bool=False) -> Optional[list[str]]:
        assert isinstance(asn, str) and asn.isdecimal()
        assert isinstance(provider, bool) and isinstance(customer, bool)
        assert (provider and customer) == False

        try:
            as_class = self.as_class_list.get_AS(asn)
        except KeyError:
            return None

        adj_as_list = []
        for c in self.connection_list:
            if asn == c["src"] and (not provider):
                adj_as_list.append(c["dst"])
            elif asn == c["dst"] and (not customer):
                adj_as_list.append(c["src"])
        return adj_as_list

    def as_a_is_what_on_c(self, as_a, connection_c) -> Optional[str]:
        if connection_c["type"] == "peer":
            return "peer"
        elif connection_c["type"] == "down":
            if as_a == connection_c["src"]:
                return "provider"
            elif as_a == connection_c["dst"]:
                return "customer"
        return None

    def run(self) -> None:
        for as_class in self.as_class_list.get_AS_list().values(): # To reference public_aspa_list when ASPV
            as_class.set_public_aspa(self.public_aspa_list)

        while not self.message_queue.empty():
            m = self.message_queue.get()
            if m["type"] == "update":
                as_class = self.as_class_list.get_AS(m["dst"])

                # search src-dst connection
                connection_with_dst = self.get_connection_with(m["dst"])
                connection = None
                for c in connection_with_dst:
                    if m["src"] in [c["src"], c["dst"]]:
                        connection = c
                        break
                assert connection is not None # debug; var connection should not be None.

                # peer, customer or provider
                m["come_from"] = self.as_a_is_what_on_c(m["src"], connection)

                route_diff = as_class.update(m)
                if route_diff == None:
                    continue
                if route_diff["come_from"] == "customer":
                    for c in connection_with_dst:
                        new_update_message = {}
                        new_update_message["type"] = "update"
                        new_update_message["src"] = m["dst"]
                        new_update_message["path"] = route_diff["path"]
                        new_update_message["network"] = route_diff["network"]
                        tmp = [c["src"], c["dst"]]
                        tmp.remove(m["dst"])
                        new_update_message["dst"] = tmp[0]
                        self.message_queue.put(new_update_message)
                elif route_diff["come_from"] == "peer" or route_diff["come_from"] == "provider":
                    for c in connection_with_dst:
                        if c["type"] == "down" and c["src"] == m["dst"]:
                            new_update_message = {}
                            new_update_message["type"] = "update"
                            new_update_message["src"] = m["dst"]
                            new_update_message["dst"] = c["dst"]
                            new_update_message["path"] = route_diff["path"]
                            new_update_message["network"] = route_diff["network"]
                            self.message_queue.put(new_update_message)

            elif m["type"] == "init":
                for c in self.get_connection_with(m["src"]):
                    m["come_from"] = self.as_a_is_what_on_c(m["src"], c)
                    tmp = [c["src"], c["dst"]]
                    tmp.remove(m["src"])
                    new_update_message_list = self.as_class_list.get_AS(tmp[0]).receive_init(m)
                    for new_m in new_update_message_list:
                        self.message_queue.put(dict({"type": "update"}, **new_m))

    def export(self, filename:str) -> None:
        assert isinstance(filename, str) and filename != ""
        export_content = {}

        export_content["AS_list"] = []
        class_list = self.as_class_list.get_AS_list()
        for v in class_list.values():
            export_content["AS_list"].append({"AS": v.as_number, "network_address": v.network_address, "policy": v.policy, "routing_table": v.routing_table.get_table()})

        export_content["IP_gen_seed"] = self.as_class_list.ip_gen.index

        export_content["message"] = []
        tmp_queue = queue.Queue()
        while not self.message_queue.empty():
            q = self.message_queue.get()
            export_content["message"].append(q)
            tmp_queue.put(q)
        self.message_queue = tmp_queue

        export_content["connection"] = self.connection_list

        export_content["ASPA"] = self.public_aspa_list

        with open(filename, mode="w") as f:
            yaml.dump(export_content, f)

    def file_import(self, filename:str) -> None:
        assert isinstance(filename, str) and filename != ""
        try:
            with open(filename, mode="r") as f:
                import_content = yaml.safe_load(f)
        except FileNotFoundError as e:
            print(f"Error: No such file or directory: {filename}", file=sys.stderr)
            return None

        self.as_class_list.import_AS_list(import_content["AS_list"])
        self.as_class_list.ip_gen.index = import_content["IP_gen_seed"]
        self.message_queue = queue.Queue()
        for m in import_content["message"]:
            self.message_queue.put(m)
        self.connection_list = import_content["connection"]
        self.public_aspa_list = import_content["ASPA"]

    def chain_search_ASPA(self, customer_as):

        try:
            prov_list = self.public_aspa_list[customer_as]
        except KeyError:
            return [customer_as]
        if str(prov_list[0]) == "0":
            return [customer_as]

        ret_list = []
        for prov in prov_list:
            ret_list.extend(self.chain_search_ASPA(prov))
        edited_list = [f"{ret}-{customer_as}" for ret in ret_list]
        return edited_list

    def genAttack(self, src:str, target:str, ASPA_utilize:bool=False):
        assert isinstance(src, str) and src.isdecimal()
        assert isinstance(target, str) and target.isdecimal()
        assert isinstance(ASPA_utilize, bool)

        try:
            self.as_class_list.get_AS(src)
        except KeyError:
            assert False, f"Error: AS {src} is NOT registered"
            return

        try:
            target_as_class = self.as_class_list.get_AS(target)
        except KeyError:
            assert False, f"Error: AS {target} is NOT registered"
            return

        src_connection_list = self.get_connection_with(src)
        adj_as_list = []
        for c in src_connection_list:
            if src == c["src"]:
                adj_as_list.append(c["dst"])
            else:
                adj_as_list.append(c["src"])

        target_address = target_as_class.network_address

        attack_path_list = []
        if ASPA_utilize:
            generated_path = self.chain_search_ASPA(target)
            attack_path_list = [f"{src}-{path}" for path in generated_path]
        else:
            attack_path_list.append(f"{src}-{target}")

        for path in attack_path_list:
            for adj_as in adj_as_list:
                self.message_queue.put({"type": "update", "src": src, "dst": str(adj_as), "path": path, "network": str(target_address)})

    def genOutsideAttack(self, via_asn:str, target_asn:str, hop:int, ASPA_utilize:bool=False) -> None:
        assert isinstance(ASPA_utilize, bool)
        assert isinstance(via_asn, str) and via_asn.isdecimal()
        assert isinstance(target_asn) and target_asn.isdecimal()
        assert isinstance(hop, int)

        if not(via_asn in self.as_class_list.class_list.keys()):
            print(f"AS {via_asn} has not been registerd.")
            return

        if not(target_asn in self.as_class_list.class_list.keys()):
            print(f"AS {target_asn} has not been registerd.")
            return
        else:
            target_as_class = self.as_class_list.get_AS(target_asn)

        outside_as = OUTSIDE_AS
        while True:
            try:
                self.as_class_list.get_AS(OUTSIDE_AS)
                outside_as += 1
            except KeyError:
                break

        self.as_class_list.add_AS(str(outside_as))
        self.connection_list.append({"type": "down", "src": via_asn, "dst": str(outside_as)})

        target_address = target_as_class.network_address

        attack_path_list = []
        if ASPA_utilize:
            generated_path = self.chain_search_ASPA(target_asn)
            attack_path_list = [f"{outside_as}-{path}" for path in generated_path]
        else:
            attack_path_list.append(f"{outside_as}-{target}")

        for path in attack_path_list:
            self.message_queue.put({"type":"update", "src":str(outside_as), "dst":str(via_asn), "network":str(target_address)})

    def autoASPA(self, customer_asn:str, hop_number:int) -> None:
        assert isinstance(customer_asn, str)
        assert isinstance(hop_number, int)

        try:
            self.as_class_list.get_AS(customer_asn)
        except KeyError:
            print(f"Error: AS {str(customer_asn)} is NOT registered.", file=sys.stderr)
            return

        customer_as_list = [customer_asn]

        while hop_number != 0 and len(customer_as_list) != 0:
            next_customer_as_list = []
            for customer_as in customer_as_list:
                c_list = self.get_connection_with(customer_as)

                provider_list = []
                for c in c_list:
                    if self.as_a_is_what_on_c(customer_as, c) == "customer":
                        provider_list.append(c["src"])

                next_customer_as_list += provider_list

                if len(provider_list) == 0:
                    provider_list = [0]

                self.public_aspa_list[customer_as] = provider_list

            hop_number -= 1
            customer_as_list = list(set(next_customer_as_list))

    def autoASPV(self, asn:str, hop_number:int, priority:Optional[str]=None) -> None:
        assert isinstance(asn, str) and asn.isdecimal()
        assert isinstance(hop_number, int)
        assert hop_number > 0

        to_be_deploy_aspv_as_list = [asn]
        while hop_number != 0 and len(to_be_deploy_aspv_as_list) != 0:
            next_adj_as_list = []
            for to_be_deploy_aspv_as in to_be_deploy_aspv_as_list:
                c_list = self.get_connection_with(to_be_deploy_aspv_as)

                adj_as_list = []
                for c in c_list:
                    if to_be_deploy_aspv_as == c["src"]:
                        adj_as_list.append(c["dst"])
                    elif to_be_deploy_aspv_as == c["dst"]:
                        adj_as_list.append(c["src"])

                next_adj_as_list += adj_as_list

                self.setASPV(to_be_deploy_aspv_as, "on", priority)
            hop_number -= 1
            to_be_deploy_aspv_as_list = list(set(next_adj_as_list))




# usage example
if __name__ == "__main__":
    print("\033[43m\033[31mThis file should NOT be executed directly. IMPORT this file as a module instead.\033[39m\033[49m")
