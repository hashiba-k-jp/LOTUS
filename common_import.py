class IP_address_generator:
  def __init__(self):
    self.index = 1 # To generate unique address

  def get_unique_address(self):
    address = "10." + str(self.index // 256) + "." + str(self.index % 256) + ".0/24"
    self.index += 1
    return address

class LOTUSInputError(Exception):
  # Exception class for application-dependent error
  pass

class BestPathNotExist(Exception):
  pass
