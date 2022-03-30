import os
import re
import subprocess

apache2_config_file = "/etc/apache2/apache2.conf"


def section10():
    print("### Start of Section 10 ###\n")
    search_reg_exp = [r"^512$", r"^100$", r"^1024$", r"^102400$"]
    expected_values = ["512", "100", "1024", "102400"]
    directive_lines = ["LimitRequestLine 512", "LimitRequestFields 100", "LimitRequestFieldSize 1024",
                       "LimitRequestBody 102400"]
    directives = ["LimitRequestLine", "LimitRequestFields", "LimitRequestFieldSize", "LimitRequestBody"]
    found = [False, False, False, False]
    changed = [False, False, False, False]

    try:
        with open(apache2_config_file + ".new", "w+") as output_file:
            with open(apache2_config_file, "r") as input_file:
                original_content = input_file.readlines()
                for original_line in original_content:
                    for i in range(0, 4):
                        # If directive is in current line
                        if directives[i] in original_line:
                            limit_req_line = original_line.split()
                            original_value = limit_req_line[1]

                            # Don't change the original value if it's correct.
                            if re.match(search_reg_exp[i], original_value):
                                found[i] = True
                                print(directives[i] + " already has a value of " + expected_values[i])

                            # Change the original value if it's incorrect.
                            else:
                                changed[i] = True
                                output_file.write(
                                    directive_lines[i] + " # Corrected value from " + original_value + " to " +
                                    expected_values[i] + "\n")  # Write the correct directive line.
                                print("Changed line: " + original_line.rstrip() + " --> " +
                                      directive_lines[i])  # Print all changed lines.
                                original_line = ""  # Remove original line

                    output_file.write(original_line)  # Restore the rest of the original config file.

            output_file.write("\n### Start of Added Directives for Section 10  of CIS Benchmark ###\n\n")
            for j, found_bool in enumerate(found):
                if not found_bool and not changed[j]:
                    # If directive doesn't exist in config, write to last line of new config
                    output_file.write(directive_lines[j] + "\n")
                    print("Added line: " + directive_lines[j])  # Print all added lines.
            output_file.write("\n### End of Added Directives for Section 10  of CIS Benchmark ###\n")
            print(
                "\nAll changes are saved to " + apache2_config_file + ".new. To reflect all changes, manually rename this file to apache2.conf.")
    except FileNotFoundError as e:
        print("Apache Config File not found.")
    print("\n### End of Section 10 ###")


def main():
    global apache2_config_file
    if os.path.exists(apache2_config_file):
        print("Apache Config File Found")

    else:
        apache2_config_file = input('Enter Configuration File Location: ')

    get_user_id = "id -u"
    process = subprocess.Popen(get_user_id.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    user_id = int(output.decode().rstrip())

    if user_id != 0:
        print("Not root. Please run as root.")
    else:
        section10()


main()
