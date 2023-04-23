# SimpleSEIM
SimpleSEIM: An open-source, modular SEIM (Security Event Information Manager) in python.


SimpleSEIM script parses a log file (in this case, the file located at /var/log/auth.log) and extracts the IP addresses from it. It then counts the occurrences of each IP address in the log file, and if an IP address appears more than 5 times, it performs a remediation action by using the iptables command to block traffic from that IP address.

The script defines three functions: parse_log() to extract the IP addresses from the log file, analyze_log_data() to count the occurrences of each IP address, and perform_remediation_action() to block traffic from an IP address using iptables. The script then calls these functions in sequence to perform the desired analysis and remediation.

SimpleSEIM can manage remediation and abides by specific rules set in the code but these rules and remediation actions are modular in that the script is open-source and easily modified to add these actions and rules.

SimpleSEIM is developed by @abtzpro, @AdamR, and Hello Security as an open source building block for a modular yet simplistic SEIM. 
