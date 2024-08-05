import os
import shutil
import stat
import git
import Main
import Test
import base64

def delete_directory_if_exists(directory):
    """Delete the directory and its contents if it exists."""
    if os.path.exists(directory):
        print(f"Deleting existing directory: {directory}")

        def remove_readonly(func, path, _):
            """Helper function to remove read-only attribute before deleting."""
            os.chmod(path, stat.S_IWRITE)
            func(path)

        try:
            shutil.rmtree(directory, onerror=remove_readonly)
            print(f"Successfully deleted '{directory}'")
        except Exception as e:
            print(f"Error deleting directory '{directory}': {e}")

# Parameters
repo_url = 'https://github.com/pavankalyanvarikolu/terraform-infra.git'
repo_dir = 'C:/Users/pavan/Downloads/FINAL PAVANCODE-1/FINAL PAVANCODE/terraform-infra'
report_file = 'vulnerability_report.txt'  # File to store the output

# Clone the repository
def clone_repo(repo_url, repo_dir):
    delete_directory_if_exists(repo_dir)  # Ensure the directory is clean before cloning
    try:
        repo = git.Repo.clone_from(repo_url, repo_dir)
        print(f"Repository cloned to '{repo_dir}'.")
        return repo
    except git.exc.GitCommandError as e:
        print(f"Git command failed: {e}")
        return None

# Clone the repository
repo = clone_repo(repo_url, repo_dir)

# If cloning was successful, read and store .tf files content
if repo:
    def read_tf_files_recursive(directory):
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
                        print(f"Error reading file {file_path}: {e}")

        return tf_files_content

    tf_files = read_tf_files_recursive(repo_dir)

    # Open the report file in write mode
    with open(report_file, 'w') as report:
        for file_path, content in tf_files.items():
            report.write(f"--- Content of {file_path} ---\n")
            vul = Main.predict_vulnerabilities(content)
            report.write(f"Vulnerability report for {file_path}:\n{vul}\n")
            report.write("\n")  # Add an extra line for better readability
            print(f"Vulnerabilities for {file_path}: {vul}")

    print(f"Vulnerability report has been saved to '{report_file}'")

    # Send the email using pre-generated OAuth credentials
    def save_token_from_base64(encoded_token):
        with open('token.json', 'wb') as token_file:
            token_file.write(base64.b64decode(encoded_token))

    def authenticate_gmail():
        SCOPES = ['https://www.googleapis.com/auth/gmail.send']
        save_token_from_base64(os.getenv('GMAIL_TOKEN_BASE64'))
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        service = build('gmail', 'v1', credentials=creds)
        return service

    # Send email if service is successfully authenticated
    try:
        service = authenticate_gmail()
        Test.send_message(service, "kalyanvarikolu@gmail.com", "Vulnerability Report", "Please find the attached report.", [report_file])
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

