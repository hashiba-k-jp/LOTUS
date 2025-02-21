import re

class BestPathNotExist(Exception):
    pass

class Routing_table:
    def __init__(self, network, policy):
        self.table = {}
        self.table[network] = [{"path": "i", "come_from": "customer", "LocPrf": 1000, "best_path": True}]
        self.policy = policy
        self.aspa_list = {}

    def change_policy(self, policy):
        self.policy = policy

    def set_public_aspa(self, public_aspa_list):
        self.aspa_list = public_aspa_list

    # MEMO    : This function MUST return one of ["Unknown", "Valid", "Invalid"]
    def verify_pair(self, customer_as, provider_as):
        try:
            candidate_provider_list = self.aspa_list[customer_as]
        except KeyError:
            return "Unknown"

        if provider_as in candidate_provider_list:
            return "Valid"
        else:
            return "Invalid"

    def aspv(self, route, neighbor_as):

        ###
        ### Referencing Internet-Draft draft-ietf-sidrops-aspa-verification-08
        ### https://www.ietf.org/archive/id/draft-ietf-sidrops-aspa-verification-08.txt
        ###

        p = route["path"]
        path_list = p.split("-")

        if route["come_from"] in ["customer", "peer"]:

            if path_list[0] != neighbor_as:
                return "Invalid"

            try:
                index = -1
                semi_state = "Valid"
                while True:
                    pair_check = self.verify_pair(path_list[index], path_list[index - 1])
                    if pair_check == "Invalid":
                        return "Invalid"
                    elif pair_check == "Unknown":
                        semi_state = "Unknown"
                    index -= 1
            except IndexError:  # the end of checking
                pass

            return semi_state

        elif route["come_from"] == "provider":

            if path_list[0] != neighbor_as:
                return "Invalid"

            try:
                index = -1
                semi_state = "Valid"
                upflow_fragment = True
                while True:
                    if upflow_fragment == True:
                        pair_check = self.verify_pair(path_list[index], path_list[index - 1])
                        if pair_check == "Invalid":
                            upflow_fragment = False
                        elif pair_check == "Unknown":
                            semi_state = "Unknown"
                        index -= 1
                    elif upflow_fragment == False:
                        # I-D version: It is thought to be wrong.
                        # pair_check = self.verify_pair(path_list[index - 1], path_list[index])
                        pair_check = self.verify_pair(path_list[index], path_list[index + 1])
                        if pair_check == "Invalid":
                            return "Invalid"
                        elif pair_check == "Unknown":
                            semi_state = "Unknown"
                        index -= 1
            except IndexError:  # the end of checking
                pass

            return semi_state

        else:
            assert False, f"Invalid route sender : {route["""come_from"""]}"

    def update(self, update_message):
        network = update_message["network"]
        path = update_message["path"]
        come_from = update_message["come_from"]

        # QUESTION: ここの値(50, 100, 200)はなんらかのRFCで定められている？もしくは慣習的なものか、このLOTUSの実装で適当に定められたものか？
        if come_from == "peer":
            locpref = 100
        elif come_from == "provider":
            locpref = 50
        elif come_from == "customer":
            locpref = 200

        new_route = {"path": path, "come_from": come_from, "LocPrf": locpref}

        if "aspv" in self.policy:
            new_route["aspv"] = self.aspv(new_route, update_message["src"])

        try:
            new_route["best_path"] = False
            self.table[network].append(new_route)

            # select best path
            best = None
            for r in self.table[network]:
                if r["best_path"] == True:
                    best = r
                    break
            if best == None:
                raise BestPathNotExist

            for p in self.policy:
                if p == "LocPrf":
                    if new_route["LocPrf"] > best["LocPrf"]:
                        new_route["best_path"] = True
                        best["best_path"] = False
                        return {"path": new_route["path"], "come_from": new_route["come_from"], "network": network}
                    elif new_route["LocPrf"] == best["LocPrf"]:
                        continue
                    elif new_route["LocPrf"] < best["LocPrf"]:
                        return None
                elif p == "PathLength":
                    new_length = len(new_route["path"].split("-"))
                    best_length = len(best["path"].split("-"))
                    if new_length < best_length:
                        new_route["best_path"] = True
                        best["best_path"] = False
                        return {"path": new_route["path"], "come_from": new_route["come_from"], "network": network}
                    elif new_length == best_length:
                        continue
                    elif new_length > best_length:
                        return None
                elif p == "aspv":
                    if new_route["aspv"] == "Invalid":
                        return None
                else:
                        assert False, f"Invalid routing policy : {p}"

        # QUESTION: ここのexceptionはどこで入る？ new_route["aspv"] でKeyErrorになりうるけどその時には self.table[network] = [new_route] は何？
        # MEMO    : 割と最初の self.table[network] でそもそもそのNWにrouteが登録されていない時っぽい。** new_route["aspv"] ではKeyErrorにはなり得ない。**
        except KeyError:
            if self.policy[0] == "aspv":
                if new_route["aspv"] == "Invalid":
                    new_route["best_path"] = False
                    self.table[network] = [new_route]
                    return None
                else:
                    new_route["best_path"] = True
                    self.table[network] = [new_route]
                    return {"path": path, "come_from": come_from, "network": network}
            else:
                new_route["best_path"] = True
                self.table[network] = [new_route]
                return {"path": path, "come_from": come_from, "network": network}

        except BestPathNotExist:
            if self.policy[0] == "aspv":
                if new_route["aspv"] == "Invalid":
                    return None
                else:
                    new_route["best_path"] = True
                    return {"path": path, "come_from": come_from, "network": network}
            else:
                new_route["best_path"] = True
                return {"path": path, "come_from": come_from, "network": network}

    def get_best_path_list(self):

        best_path_list = []

        for network in self.table.keys():
            for route in self.table[network]:
                if route["best_path"] == True:
                    best_path_list.append(dict({"network": network}, **route))

        return best_path_list

    def get_table(self):
        return self.table
