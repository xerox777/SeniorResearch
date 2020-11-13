from scapy.all import *    # This is needed for the .cap analyzing
import re   # This is for the regular expressions
from subprocess import Popen
from subprocess import check_output 
import queue
# -*- coding: utf-8 -*-
#reg_exp_arr = []
result = {} # To store results from each thread
class pcap_team:
    #reg_exp_arr = []
    #condensed_re = ""
    def __init__(self, team_name, team_file):
        self.team_name = team_name
        self.team_file = team_file + ".txt" # Assumes that team_file does not have .txt to begin with
        self.team_folder = team_file
        self.reg_exp_arr = []
        self.result = []
    def scapy_search(self):
        #team = input("Specify team name: ")
        # Get team name then filter tokens specific to this team name to do further analyzing on
        # file = open("scoreboard.txt", "r")
        # parse scoreboard output for teamname and token value, etc.
        tt = open("team_tokens.txt", "w")
        with open("scoreboard.txt") as fp:
            line = fp.readline()
            # get the tokens and their owners to use for creating regular expressions
            while line:
                owner = str(line).split("owner': '", 1)[1]
                owner = owner.split("', 'exploiter'", 1)[0]
                # TODO use the owners to go to their pcap folder and look through files
                token = str(line).split("token': '", 1)[1]
                token = token.split("', 'owner'", 1)[0]
                # TODO use tokens to create regular expressions
                print(owner)
                if (self.team_name in owner):
                    tt.write(token + "\n")
                    tt.write(owner + "\n")
                line = fp.readline()

        # Read from team_tokens.txt, every odd number is a token and the even number after the token is the owner
        t_dict = {}
        with open("team_tokens.txt") as t_tokens:
            line = t_tokens.readline().rstrip()
            count = 1
            line2 = "1"
            dec = 1
            while line:
                line2 = t_tokens.readline().rstrip()
                if (count % 2 == 0):
                    dec = dec + 1
                line2 = line2 + str(dec)
                if (count % 2 == 1):
                    t_dict[line2] = line
                count += 1
                line = t_tokens.readline().rstrip()
        print(t_dict)
        # Reading from the dictionary, make a regular expression out of tokens and search all files for it
        dict_length = len(t_dict)
        reg_exp_arr = []
        condensed_re = ""
        for i in range(1, dict_length + 1):
            # Index must have team name specified
            index = self.team_name
            index = index + str(i)
            reg_exp = t_dict[index]
            final_re = r""
            final_re += "("
            for char in reg_exp:
                final_re += "["
                final_re += char
                final_re += "]"
                final_re += "["
                final_re += "\\"
                final_re += "w"
                final_re += "]"
            final_re += ")|"
            reg_exp_arr.append(final_re)
            condensed_re += final_re
        team_subnet = open("team_subnet.txt", "w")
        reg_exp = list(dict.fromkeys(reg_exp))
        condensed_re = condensed_re[:-1]
        print(condensed_re)
        condensed_re = re.compile(condensed_re)
        with open(self.team_file, "r") as dragon:
            line = "/Users/macbook/Desktop/ssu/LAST_SEMESTER/cs496/defconscorelib/pcaps/" + self.team_folder + "/" + dragon.readline().rstrip()
            while line:
                packets = rdpcap(line)
                for pkt in packets:
                    # ind = len(reg_exp_arr)
                    # for x in range (0, ind):
                    regexp = condensed_re.findall(pkt.show(dump=True))
                    # reg_comp = re.compile(condesned_re
                    # reg_comp.findall(pkt)
                    if (regexp):
                        print(regexp)
                        print("source port = " + str(pkt[IP].src))
                        print(line)
                        team_subnet.write(str(regexp))
                        team_subnet.write("\nsource ip = " + str(pkt[IP].src))
                        team_subnet.write("\nfile = " + line)
                        team_subnet.write("\nDest ip = " + str(pkt[IP].dst))
                line = "/Users/macbook/Desktop/ssu/LAST_SEMESTER/cs496/defconscorelib/pcaps/" + self.team_folder + "/" + dragon.readline().rstrip()


    def ngrep(self):
       team = self.team_name
       # parse scoreboard output for teamname and token value, etc.
       #tt = open("team_tokens.txt", "w")
       with open("scoreboard.txt") as fp:
          line = fp.readline()
          # get the tokens and their owners to use for creating regular expressions
          tt = []
          while line:
             owner = str(line).split("owner': '", 1)[1]
             owner = owner.split("', 'exploiter'", 1)[0]
             #TODO use the owners to go to their pcap folder and look through files
             token = str(line).split("token': '", 1)[1]
             token = token.split("', 'owner'", 1)[0]
             #TODO use tokens to create regular expressions
             print(owner)
             if(team in owner):
                tt.append(token)
                tt.append(owner)
		#tt.write(token + "\n")
                #tt.write(owner + "\n")
             line = fp.readline()

       # Read from team_tokens.txt, every odd number is a token and the even number after the token is the owner
       t_dict = {}
       for i in range(0, len(tt)-1, 2):    # Iterate through array of owners/tokens
          line = tt[i]
          line2 = tt[i+1]
          line2 = line2 + str(i)
          t_dict[line2] = line

       print(t_dict)
       # Reading from the dictionary, make a regular expression out of tokens and search all files for it
       dict_length = len(t_dict)
       condensed_re = ""
       for i in range(0, dict_length-1, 2):
          # Index must have team name specified
          index = self.team_name
          index = index + str(i)
          reg_exp = t_dict[index]
          final_re = r""
          #final_re += "("
          for char in reg_exp:
             final_re += char
             final_re += "."
          #final_re += ")|"
          self.reg_exp_arr.append(final_re)
          condensed_re += final_re
       print(self.reg_exp_arr)
       team_subnet = open("team_subnet.txt", "w")
       #reg_exp = list( dict.fromkeys(self.reg_exp_arr))
       condensed_re = condensed_re[:-1]
       print(condensed_re)
       inc = 0
       with open(self.team_file, "r") as dragon:
            #line = "/kirby/ssu_seclab/ctf-corpus/DEFCON22-2014-08/pcaps/dragonsector/" + dragon.readline().rstrip()
            fn = dragon.readline() 
            line = "/Users/macbook/Desktop/ssu/LAST_SEMESTER/cs496/defconscorelib/pcaps/" + self.team_folder + "/" + fn.rstrip()
            while fn:
                inc2 = 0
                for cur_re in self.reg_exp_arr:
                    cmd = "ngrep -d any -q -I "
                    _cmd = cmd + str(line) + " \"" + str(cur_re) + "\""
                    # processes = Popen(str(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    # stdout = processes.communicate()
                    try:
                        # out = check_output(str(_cmd), shell=True)
                        #out_grep.write(_cmd)
                        process = Popen(str(_cmd), stdout=subprocess.PIPE, shell=True)
                        process.wait()
                        out, err = process.communicate()
                        print(out)
                        #out_grep = open("grepfile.txt", "a")
                        #out_grep.write(out.decode('utf-8'))
                        self.result.append(out.decode('utf-8'))
                        #out_grep.fflush()
                        #out_grep.close()
                        for _line in out.decode('utf-8'):
                            print(_line)

                    except:
                        print("Grep did not find match")
                    inc2 = inc2 + 1
                inc = inc + 1
                fn = dragon.readline()
                #line = "/kirby/ssu_seclab/ctf-corpus/DEFCON22-2014-08/pcaps/dragonsector/" + dragon.readline().rstrip()
                line = "/Users/macbook/Desktop/ssu/LAST_SEMESTER/cs496/defconscorelib/pcaps/" + self.team_folder + "/" + fn.rstrip()


    def print_results(self):
      #global result
      out_grep = open("grepfile.txt", "w")
      for i in range(0, len(self.result)-4):
         if (" -> " in self.result[i] ):
             out_grep.write(self.result[i])
      out_grep.close()

def thread_call():
  dragon = pcap_team("Dragon Sector", "dragonsector")
  #dragon.main()
  #threads = [ threading.Thread(target=dragon.scapy_search) for i in range(20) ]
  dragon.ngrep()
  dragon.print_results()
  """dragon.scapy_search()
  threads = [threading.Thread(target=dragon.scapy_search) for i in range(2)]
  for thread in threads:
     thread.start()
  for thread in threads:
     thread.join()"""

      


thread_call()
#print_results()
