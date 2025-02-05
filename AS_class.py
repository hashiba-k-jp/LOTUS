import sys

from routing_table import Routing_table

class IP_address_generator:
  def __init__(self):
    self.index = 1 # To generate unique address

  def get_unique_address(self):
    address = "10." + str(self.index // 256) + "." + str(self.index % 256) + ".0/24"
    self.index += 1
    return address

class AS_class_list:
  def __init__(self):
    self.class_list = {}
    self.ip_gen = IP_address_generator()

  def add_AS(self, as_number):
    if not as_number in self.class_list.keys():
      self.class_list[as_number] = AS_class(as_number, self.ip_gen.get_unique_address())
    else:
      print("Error: AS " + str(as_number) + " is already registered.", file=sys.stderr)

  def show_AS_list(self, sort_flag, best_flag, address):

    keys = list(self.class_list.keys())
    if sort_flag == True:
      keys.sort()

    for k in keys:
      self.class_list[k].show_info(only_best=best_flag, address=address)

  def get_AS(self, as_number):
    return self.class_list[as_number]

  def get_AS_list(self):
    return self.class_list

  def import_AS_list(self, import_list):

    self.class_list = {}
    for a in import_list:
      self.class_list[a["AS"]] = AS_class(a["AS"], a["network_address"])
      self.class_list[a["AS"]].policy = a["policy"]
      self.class_list[a["AS"]].routing_table.change_policy(a["policy"])
      self.class_list[a["AS"]].routing_table.table = a["routing_table"]

class AS_class:
  def __init__(self, asn, address):
    self.as_number = asn
    self.network_address = address
    self.policy = ["LocPrf", "PathLength"]
    self.routing_table = Routing_table(self.network_address, self.policy)

  def show_info(self, only_best=False, address=None):
    print("====================")
    print(f"AS NUMBER: {self.as_number}")
    print(f"network: {self.network_address}")
    print(f"policy: {self.policy}")

    table = self.routing_table.get_table()
    addr_list = []
    if address == None:
      for addr in table.keys():
        addr_list.append(ipaddress.ip_network(addr))
      addr_list.sort()
    else:
      addr_list.append(address)

    print("routing table: (best path: > )")
    for addr in addr_list:
      print(str(addr) + ":")
      try:
        for r in table[str(addr)]:
          path = r["path"]
          come_from = r["come_from"]
          LocPrf = r["LocPrf"]
          try:
            aspv = r["aspv"]
            if r["best_path"] == True:
              print(f"> path: {path}, LocPrf: {LocPrf}, come_from: {come_from}, aspv: {aspv}")
            elif only_best == True:
              continue
            else:
              print(f"  path: {path}, LocPrf: {LocPrf}, come_from: {come_from}, aspv: {aspv}")
          except KeyError:
            if r["best_path"] == True:
              print(f"> path: {path}, LocPrf: {LocPrf}, come_from: {come_from}")
            elif only_best == True:
              continue
            else:
              print(f"  path: {path}, LocPrf: {LocPrf}, come_from: {come_from}")
      except KeyError:
        print("No-Path")
    print("====================")

  def set_public_aspa(self, public_aspa_list):
    self.routing_table.set_public_aspa(public_aspa_list)

  def update(self, update_message):
    if self.as_number in update_message["path"].split("-"):
      return

    route_diff = self.routing_table.update(update_message)
    if route_diff == None:
      return
    else:
      route_diff["path"] = str(self.as_number) + "-" + route_diff["path"]
      return route_diff

  def change_ASPV(self, message):
    if message["switch"] == "on":
      self.policy = ["LocPrf", "PathLength"]
      self.policy.insert(int(message["priority"]) - 1, "aspv")
    elif message["switch"] == "off":
      self.policy = ["LocPrf", "PathLength"]
    self.routing_table.change_policy(self.policy)

  def receive_init(self, init_message):
    best_path_list = self.routing_table.get_best_path_list()
    new_update_message_list = []
    update_src = self.as_number
    update_dst = init_message["src"]
    if init_message["come_from"] == "customer":
      for r in best_path_list:
        if r["path"] == "i": # the network is the AS itself
          new_update_message_list.append({"src": update_src, "dst": update_dst, "path": update_src, "network": r["network"]})
        else:
          new_update_message_list.append({"src": update_src, "dst": update_dst, "path": update_src + "-" + r["path"], "network": r["network"]})
    else:
      for r in best_path_list:
        if r["come_from"] == "customer":
          if r["path"] == "i": # the network is the AS itself
            new_update_message_list.append({"src": update_src, "dst": update_dst, "path": update_src, "network": r["network"]})
          else:
            new_update_message_list.append({"src": update_src, "dst": update_dst, "path": update_src + "-" + r["path"], "network": r["network"]})
    return new_update_message_list
