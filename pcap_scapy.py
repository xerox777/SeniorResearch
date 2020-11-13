from scapy.all import *    # This is needed for the .cap analyzing
import re   # This is for the regular expressions
def main():
   team = input("Specify team name: ")
   # Get team name then filter tokens specific to this team name to do further analyzing on
   #file = open("scoreboard.txt", "r")
   # parse scoreboard output for teamname and token value, etc.
   tt = open("team_tokens.txt", "w")
   with open("scoreboard.txt") as fp:
      line = fp.readline()
      # get the tokens and their owners to use for creating regular expressions
      while line:
         owner = str(line).split("owner': '", 1)[1]
         owner = owner.split("', 'exploiter'", 1)[0]
         #TODO use the owners to go to their pcap folder and look through files
         token = str(line).split("token': '", 1)[1]
         token = token.split("', 'owner'", 1)[0]
         #TODO use tokens to create regular expressions
         print(owner)
         if(team in owner):
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
         if(count % 2 == 0):
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
   for i in range(1, dict_length+1):
      # Index must have team name specified
      index = "Dragon Sector"
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
   reg_exp = list( dict.fromkeys(reg_exp))
   condensed_re = condensed_re[:-1]
   print(condensed_re)
   condensed_re = re.compile(condensed_re)
   with open("dragonsector.txt", "r") as dragon:
      line = "pcaps/dragonsector/" + dragon.readline().rstrip()
      while line:
         packets = rdpcap(line)
         for pkt in packets:   
            #ind = len(reg_exp_arr)
            #for x in range (0, ind):
	    
            regexp = condensed_re.findall(pkt.show(dump=True))
	       #reg_comp = re.compile(condesned_re
	       #reg_comp.findall(pkt)
            if(regexp):
               print(regexp)
               print("source port = " + str(pkt[IP].src))
               print(line)
               team_subnet.write(str(regexp))
               team_subnet.write("\nsource ip = " + str(pkt[IP].src))
               team_subnet.write("\nfile = " + line)
               team_subnet.write("\nDest ip = " + str(pkt[IP].dst))
         line = "pcaps/dragonsector/" + dragon.readline().rstrip()
	 
	

   file = open("dictionary.txt", "w")
   packets = rdpcap('hitcon_00036_20140808125530.cap')   #'hitcon_0036_20140808125530.cap')
   _int = 0
   for line in packets:
     x = line.show(dump=True)
     regexp = re.findall(r"[F][\w][Y][\w][P][\w][I][\w][X][\w][O][\w][X][\w][t][\w][5][\w][A][\w][W][\w][W][\w][V][\w]", x) 
     if (regexp):
        print(regexp)
        #print(_int)
        print("source port =" + str(line[TCP].sport))
        print("SOURCE ip=" + str(line[IP].src))
        file.write(str(line[IP].src) + ": " + str(line[TCP].sport) + "\n")
        print(line.summary())
        print(line.time)
     _int = _int + 1
main()
