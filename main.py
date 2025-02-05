import sys
import re
from cmd import Cmd
import queue
import yaml

from AS_class      import AS_class_list

class LOTUSInputError(Exception):
  # Exception class for application-dependent error
  pass

class Interpreter(Cmd):
  def __init__(self):
    super().__init__()
    self.as_class_list = AS_class_list()
    self.message_queue = queue.Queue()
    self.connection_list = []
    self.public_aspa_list = {}

  intro = """
===^^^^^^^^^^^=============================================
=== \/ \ / \/ =============================================
== - \V V V/ - ============================================
= (( ( \ / ) )) ===========================================
====== LOTUS (Lightweight rOuTing simUlator with aSpa) ====
====== 2022 Naoki Umeda at Osaka University ===============
===========================================================
"""
  prompt = "LOTUS >> "

  def do_exit(self, line):
    return True

  def do_addAS(self, line):
    if line.isdecimal():
      self.as_class_list.add_AS(line)
    else:
      print("Usage: addAS [asn]", file=sys.stderr)

  def do_showAS(self, line):
    if line.isdecimal():
      try:
        self.as_class_list.get_AS(line).show_info()
      except KeyError:
        print("Error: AS " + str(line) + " is NOT registered.", file=sys.stderr)
    else:
      print("Usage: showAS [asn]", file=sys.stderr)

  def do_showASList(self, line):

    param = line.split()

    sort_flag = False
    best_flag = False
    address = None
    try:
      if "sort" in param:
        sort_flag = True
        param.remove("sort")
      if "best" in param:
        best_flag = True
        param.remove("best")

      if len(param) == 0:
        address = None
      elif len(param) == 1 and re.fullmatch("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/[0-9][0-9]" , param[0]):
        address = param[0]
      else:
        raise LOTUSInputError

    except LOTUSInputError:
      print("Usage: showASList [sort] [best] [address]", file=sys.stderr)
      return

    self.as_class_list.show_AS_list(sort_flag, best_flag, address)

  def do_addMessage(self, line):
    try:
      if line == "":
        raise LOTUSInputError
      param = line.split()
      if len(param) == 2 and param[0] == "init" and param[1].isdecimal():          # ex) addMessage init 12
        self.message_queue.put({"type": "init", "src": str(param[1])})
      elif len(param) == 5 and param[0] == "update" and param[1].isdecimal() and \
           param[2].isdecimal() and re.fullmatch("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])/[0-9][0-9]" , param[4]): # ex) addMessage update 12 34 54-12 10.1.1.0/24
        self.message_queue.put({"type": "update", "src": str(param[1]), "dst": str(param[2]), "path": str(param[3]), "network": str(param[4])})
      else:
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: addMessage init [src_asn]", file=sys.stderr)
      print("       addMessage update [src_asn] [dst_asn] [path] [network]", file=sys.stderr)

  def do_addAllASInit(self, line):
    for as_number in self.as_class_list.get_AS_list().keys():
      self.message_queue.put({"type": "init", "src": as_number})

  def do_showMessage(self, line):
    tmp_queue = queue.Queue()
    while not self.message_queue.empty():
      q = self.message_queue.get()
      print(q)
      tmp_queue.put(q)
    self.message_queue = tmp_queue

  def do_addConnection(self, line):
    try:
      param = line.split()
      if len(param) == 3 and param[1].isdecimal() and param[2].isdecimal():
        if param[0] == "peer":
          self.connection_list.append({"type": "peer", "src": param[1], "dst": param[2]})
        elif param[0] == "down":
          self.connection_list.append({"type": "down", "src": param[1], "dst": param[2]})
        else:
          raise LOTUSInputError
      else:
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: addConnection peer [src_asn] [dst_asn]", file=sys.stderr)
      print("       addConnection down [src_asn] [dst_asn]", file=sys.stderr)

  def do_showConnection(self, line):
    for c in self.connection_list:
      print(c)

  def do_addASPA(self, line):
    param = line.split()
    try:
      if len(param) < 2:
        raise LOTUSInputError
      else:
        for p in param:
          if not p.isdecimal():
            raise LOTUSInputError
      self.public_aspa_list[param[0]] = param[1:]
    except LOTUSInputError:
      print("Usage: addASPA [customer_asn] [provider_asns...]", file=sys.stderr)

  def do_showASPA(self, line):
    if line == "":
      print(self.public_aspa_list)
    else:
      try:
        print(self.public_aspa_list[line])
      except KeyError:
        print("Error: Unknown Syntax", file=sys.stderr)

  def do_setASPV(self, line):
    param = line.split()
    try:
      if len(param) < 2:
        raise LOTUSInputError
      if not param[0].isdecimal():
        raise LOTUSInputError
      as_class = self.as_class_list.get_AS(param[0])
      if param[1] == "on":
        if re.fullmatch("1|2|3", param[2]):
          as_class.change_ASPV({"switch": "on", "priority": param[2]})
        else:
          raise LOTUSInputError
      elif param[1] == "off":
        as_class.change_ASPV({"switch": "off"})
      else:
        raise LOTUSInputError

    except LOTUSInputError:
      print("Usage: setASPV [asn] on [1/2/3]", file=sys.stderr)
      print("       setASPV [asn] off", file=sys.stderr)
    except KeyError:
      print("Error: AS " + str(param[0]) + " is NOT registered.", file=sys.stderr)

  def get_connection_with(self, as_number):
    c_list = []
    for c in self.connection_list:
      if as_number in [c["src"], c["dst"]]:
        c_list.append(c)
    return c_list

  def as_a_is_what_on_c(self, as_a, connection_c):
    if connection_c["type"] == "peer":
      return "peer"
    elif connection_c["type"] == "down":
      if as_a == connection_c["src"]:
        return "provider"
      elif as_a == connection_c["dst"]:
        return "customer"

  def do_run(self, line):

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

  def do_export(self, line):

    try:
      if line == "":
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: export [filename]", file=sys.stderr)
      return

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

    with open(line, mode="w") as f:
      yaml.dump(export_content, f)

  def do_import(self, line):

    try:
      if line == "":
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: import [filename]", file=sys.stderr)
      return

    try:
      with open(line, mode="r") as f:
        import_content = yaml.safe_load(f)
    except FileNotFoundError as e:
      print("Error: No such file or directory: " + line, file=sys.stderr)
      return

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

  def do_genAttack(self, line):

    ASPA_utilize = False
    try:
      param = line.split()
      if "utilize" in param:
        ASPA_utilize = True
        param.remove("utilize")

      if len(param) != 2:
        raise LOTUSInputError
      elif not param[0].isdecimal() or not param[1].isdecimal():
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: genAttack [utilize] [src_asn] [target_asn]", file=sys.stderr)
      return

    src = param[0]
    target = param[1]

    try:
      self.as_class_list.get_AS(src)
    except KeyError:
      print(f"Error: AS {src} is NOT registered.", file=sys.stderr)
      return

    try:
      target_as_class = self.as_class_list.get_AS(target)
    except KeyError:
      print(f"Error: AS {target} is NOT registered.", file=sys.stderr)
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
    if ASPA_utilize == True:
      generated_path = self.chain_search_ASPA(target)
      attack_path_list = [f"{src}-{path}" for path in generated_path]
    elif ASPA_utilize == False:
      attack_path_list.append(f"{src}-{target}")

    for path in attack_path_list:
      for adj_as in adj_as_list:
        self.message_queue.put({"type": "update", "src": str(src), "dst": str(adj_as), "path": path, "network": str(target_address)})

  def do_genOutsideAttack(self, line):

    ASPA_utilize = False
    try:
      param = line.split()
      if "utilize" in param:
        ASPA_utilize = True
        param.remove("utilize")

      if len(param) != 3 or not param[0].isdecimal() or not param[1].isdecimal() or not int(param[2]) == 1:
        raise LOTUSInputError
    except LOTUSInputError:
      print("Usage: genOutsideAttack [utilize] [via_asn] [target_asn] [hop_num=1]", file=sys.stderr)
      return

    via = param[0]
    target = param[1]

    try:
      self.as_class_list.get_AS(via)
    except KeyError:
      print(f"Error: AS {via} is NOT registered.", file=sys.stderr)
      return

    try:
      target_as_class = self.as_class_list.get_AS(target)
    except KeyError:
      print(f"Error: AS {target} is NOT registered.", file=sys.stderr)
      return

    outside_as = 64512  # Private AS Number
    while True:
      try:
        self.as_class_list.get_AS(str(outside_as))
        outside_as += 1
      except KeyError:
        break
    self.as_class_list.add_AS(str(outside_as))
    self.connection_list.append({"type": "down", "src": str(via), "dst": str(outside_as)})

    target_address = target_as_class.network_address

    attack_path_list = []
    if ASPA_utilize == True:
      generated_path = self.chain_search_ASPA(target)
      attack_path_list = [f"{outside_as}-{path}" for path in generated_path]
    elif ASPA_utilize == False:
      attack_path_list.append(f"{outside_as}-{target}")

    for path in attack_path_list:
      self.message_queue.put({"type": "update", "src": str(outside_as), "dst": str(via), "path": path, "network": str(target_address)})

  def do_autoASPA(self, line):

    param = line.split()
    try:
      if len(param) != 2 or not param[0].isdecimal() or not param[1].isdecimal():
        raise LOTUSInputError

      self.as_class_list.get_AS(param[0])  # Checking the AS is exist.

    except LOTUSInputError:
      print("Usage: autoASPA [asn] [hop_num]", file=sys.stderr)
      return
    except KeyError:
      print("Error: AS " + str(param[0]) + " is NOT registered.", file=sys.stderr)
      return

    customer_as_list = [param[0]]
    hop_number = int(param[1])

    while hop_number != 0 and len(customer_as_list) != 0:

      next_customer_as_list = []
      for customer_as in customer_as_list:
        c_list = self.get_connection_with(customer_as)

        provider_list = []
        for c in c_list:
          if self.as_a_is_what_on_c(customer_as, c) == "customer":
            provider_list.append(c["src"])

        next_customer_as_list += provider_list

        if len(provider_list) == 0:  # There is NOT provider AS.
          provider_list = [0]

        self.public_aspa_list[customer_as] = provider_list  # addASPA

      hop_number -= 1
      customer_as_list = list(set(next_customer_as_list))

###
### MAIN PROGRAM
###


try:
  Interpreter().cmdloop()
except KeyboardInterrupt:
  print("\nKeyboard Interrupt (Ctrl+C)")
  pass
# except:
#   pass
