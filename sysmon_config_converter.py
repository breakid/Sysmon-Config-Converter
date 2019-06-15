#!/usr/bin/env python
#
# This script is designed to read an exported Sysmon config (using 
# "Sysmon.exe -c") and convert it back into a valid XML file that can be used 
# to re-install Sysmon.
#
# Note: Some information from the original config is not included in the 
# exported file and is therefore impossible to reconstruct.
# Examples include:
#   - Comments
#   - Rule names
# 
# IMPORTANT: As of 2019-06-12, there is a bug with Sysmon where it will only 
# dump the first onmatch collection within a rulegroup (i.e., per event type)
# For instance, the SwiftOnSecurity config has both 'onmatch="include"' and 
# 'onmatch="exclude"' groups for the FileCreateTime event, but the dumped 
# Sysmon config only lists the 'onmatch: include' rules.
#
# Disclaimer:
# While it is generally frowned upon (including by me) to hand code XML
# rather than using a library, this application was simple enough I didn't 
# want to add the extra hassle (or dependency) of an additional library.
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#==============================================================================


import re
import sys
import os

# Matches an event type header that precedes a collection of associated rules
OLD_EVENT_PATT = re.compile(" - (?P<event_type>.*?)\s*onmatch: (?P<onmatch>.*)")

# Newer versions of Sysmon allow users to specify a boolean operator for the rulegroup
NEW_EVENT_PATT = re.compile(" - (?P<event_type>.*?)\s*onmatch: (?P<onmatch>.*?)\s{3,}combine rules using '(?P<operator>.*)'")

# Matches an individual rule
RULE_PATT = re.compile("\t(?P<field>.*?)\s*filter: (?P<filter>.*?)\s{3,}value: '(?P<value>.*)'")


def write_output(output_file, header_info, rules):
  schema_version = raw_input('Schema Version (found using "sysmon.exe -s"): ')

  with open(output_file, 'w') as out_file:
    out_file.writelines('<Sysmon schemaversion="%s">\n' % schema_version)
    out_file.writelines('\t<HashAlgorithms>%s</HashAlgorithms>\n' % header_info['algorithms'].lower())
    
    if header_info['check_revocation']:
      out_file.writelines('\t<CheckRevocation/>\n')
    
    out_file.writelines('\t<EventFiltering>\n')
    
    # List event types to ensure they are written to the file in matching order
    events = ['ProcessCreate', 'FileCreateTime', 'NetworkConnect', 'ProcessTerminate', 'DriverLoad', 'ImageLoad', 'CreateRemoteThread', 'RawAccessRead', 'ProcessAccess', 'FileCreate', 'RegistryEvent', 'FileCreateStreamHash', 'PipeEvent', 'WmiEvent', 'DnsQuery']
    
    for event_type in events:
      if event_type in rules:
        for operator in rules[event_type].keys():
          if operator != '':
            out_file.writelines('\t<RuleGroup name="" groupRelation="%s">\n' % operator)
          
          for onmatch in rules[event_type][operator].keys():
            out_file.writelines('\t\t<%s onmatch="%s">\n' % (event_type, onmatch))
            
            for rule in rules[event_type][operator][onmatch]:
              #print(rule)
              out_file.writelines('\t\t\t<{0} condition="{1}">{2}</{0}>\n'.format(rule['field'], rule['filter'], rule['value']))
            
            out_file.writelines('\t\t</%s>\n' % event_type)
          
          if operator != '':
            out_file.writelines('\t</RuleGroup>\n\n')
    
    out_file.writelines('\t</EventFiltering>\n')
    out_file.writelines('</Sysmon>')



def parse_file(input_file):
  output_file = os.path.splitext(input_file)[0] + '.xml'
  
  header_info = {
    'check_revocation': False
  }
  rules = {}
  
  curr_event = None
  curr_operator = None
  curr_condition = None
  
  with open(input_file, 'r') as in_file:
    for line in in_file.readlines():
      event_data = None
      
      if 'HashingAlgorithms:' in line:
        header_info['algorithms'] = line.split(':')[1].strip()
      elif 'CRL checking:' in line:
        header_info['check_revocation'] = 'enabled' in line
      elif NEW_EVENT_PATT.match(line):
        event_data = NEW_EVENT_PATT.match(line).groupdict()
      elif OLD_EVENT_PATT.match(line):
        event_data = OLD_EVENT_PATT.match(line).groupdict()
      elif RULE_PATT.match(line):
        rules[curr_event][curr_operator][curr_condition].append(RULE_PATT.match(line).groupdict())
      
      if event_data is not None:
        curr_event = event_data['event_type']
        curr_operator = event_data['operator'].lower() if 'operator' in event_data else ''
        curr_condition = event_data['onmatch']
        
        if curr_event not in rules:
          rules[curr_event] = {}
          
        if curr_operator not in rules[curr_event]:
          rules[curr_event][curr_operator] = {}
        
        if curr_condition not in rules[curr_event][curr_operator]:
          rules[curr_event][curr_operator][curr_condition] = []
  
  write_output(output_file, header_info, rules)



def main():
  if len(sys.argv) == 2:
    input_file = sys.argv[1]
    parse_file(input_file)
  else:
    print('USAGE: %s <path to sysmon config export>' % sys.argv[0])


if __name__ == '__main__':
  main()