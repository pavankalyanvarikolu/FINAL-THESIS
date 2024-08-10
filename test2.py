import os
import shutil
import stat
import git
import concurrent.futures
import logging
from Main import predict_vulnerabilities  # Assuming this is your custom vulnerability detection module

# Set up logging
logging.basicConfig(filename='remediation_script.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')


def delete_directory_if_exists(directory):
    """Delete the directory and its contents if it exists."""
    if os.path.exists(directory):
        logging.info(f"Deleting existing directory: {directory}")

        def remove_readonly(func, path, _):
            """Helper function to remove read-only attribute before deleting."""
            os.chmod(path, stat.S_IWRITE)
            func(path)

        try:
            shutil.rmtree(directory, onerror=remove_readonly)
            logging.info(f"Successfully deleted '{directory}'")
        except Exception as e:
            logging.error(f"Error deleting directory '{directory}': {e}")


def clone_repo(repo_url, repo_dir):
    delete_directory_if_exists(repo_dir)  # Ensure the directory is clean before cloning
    try:
        repo = git.Repo.clone_from(repo_url, repo_dir)
        logging.info(f"Repository cloned to '{repo_dir}'.")
        return repo
    except git.exc.GitCommandError as e:
        logging.error(f"Git command failed: {e}")
        return None


def read_tf_files_recursive(directory):
    """Recursively read all .tf files in the directory."""
    tf_files_content = {}
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.tf'):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'r') as file:
                        content = file.read()
                        tf_files_content[file_path] = content
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")
    return tf_files_content


def correct_security_group_rule_in_vpc(original_code):
    """Correct overly permissive security group rules in vpc.tf."""
    corrected_code = original_code

    # Example: Change overly permissive CIDR blocks from "0.0.0.0/0" to a more secure setting
    if "cidr_blocks = [\"0.0.0.0/0\"]" in original_code:
        corrected_code = corrected_code.replace(
            "cidr_blocks = [\"0.0.0.0/0\"]",
            "cidr_blocks = [\"192.168.1.0/24\"]"  # Replace with a more secure CIDR block
        )
        logging.info(f"Applied remediation for overly permissive security group rules in vpc.tf.")

    return corrected_code


def get_code_remediation_for_vpc(vulnerability, original_code):
    """Generate code remediation for vulnerabilities in vpc.tf."""
    cwe_name = vulnerability.get('cwe_name', '').strip()
    corrected_code = original_code

    # Apply specific remediation logic for vpc.tf
    corrected_code = correct_security_group_rule_in_vpc(corrected_code)

    return corrected_code


def process_vpc_file(file_path, content):
    """Process the vpc.tf file, generating vulnerabilities and remediations."""
    vulnerability_report_lines = []
    remediation_report_lines = []

    vulnerability_report_lines.append(f"--- Content of {file_path} ---\n")
    remediation_report_lines.append(f"--- Remediation for {file_path} ---\n")

    vul = predict_vulnerabilities(content)

    for vulnerability in vul:
        cve_id = vulnerability['cve_id']
        cwe_name = vulnerability['cwe_name']

        # Generate corrected code
        corrected_code = get_code_remediation_for_vpc(vulnerability, content)

        if corrected_code != content:  # Only include blocks where changes were made
            vulnerability_report_lines.append(f"Vulnerability report for {file_path}:\n{vulnerability}\n")
            remediation_report_lines.append(f"Original Code:\n{content}\n")
            remediation_report_lines.append(f"Corrected Code:\n{corrected_code}\n")
            remediation_report_lines.append("\n")  # Add an extra line for better readability
            break  # Stop after the first block is corrected

    return ''.join(vulnerability_report_lines), ''.join(remediation_report_lines)


def generate_vpc_report(tf_files, vulnerability_report_file, remediation_report_file):
    """Generate the vulnerability and remediation reports specifically for vpc.tf."""
    with open(vulnerability_report_file, 'w') as vulnerability_report, open(remediation_report_file,
                                                                            'w') as remediation_report:
        for file_path, content in tf_files.items():
            if 'vpc.tf' in file_path:  # Focus only on vpc.tf
                vulnerability_content, remediation_content = process_vpc_file(file_path, content)
                vulnerability_report.write(vulnerability_content)
                remediation_report.write(remediation_content)
                logging.info(f"Processed {file_path} for vulnerabilities and remediation.")
    logging.info(f"Vulnerability report has been saved to '{vulnerability_report_file}'")
    logging.info(f"Remediation report has been saved to '{remediation_report_file}'")


# Parameters
repo_url = 'https://github.com/pavankalyanvarikolu/terraform-infra.git'
repo_dir = 'C:/Users/pavan/Downloads/FINAL PAVANCODE-1/FINAL PAVANCODE/terraform-infra'
vulnerability_report_file = 'vpc_vulnerability_report.txt'  # File to store the vulnerability report for vpc.tf
remediation_report_file = 'vpc_remediation_report.txt'  # File to store the remediation report for vpc.tf

# Main logic
repo = clone_repo(repo_url, repo_dir)
if repo:
    tf_files = read_tf_files_recursive(repo_dir)
    generate_vpc_report(tf_files, vulnerability_report_file, remediation_report_file)

    # Optionally, print the content of the files (for debugging purposes)
    with open(vulnerability_report_file, 'r') as vulnerability_report:
        print(vulnerability_report.read())

    with open(remediation_report_file, 'r') as remediation_report:
        print(remediation_report.read())
