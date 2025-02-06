import os
import subprocess
from multiprocessing import Pool

def main():
  filepath = os.path.join("data", "plain")
  with open(filepath, "w") as file:
    subprocess.run(["./plain.sh"], stdout=file)

  with open(filepath, "r") as file:
    filedata = file.read()

  filedata.replace('\r', '')

  with open(filepath, "w") as file:
    file.write(filedata)
  print("saving plain FINISH")

if __name__ == '__main__':
  main()
