"""
Pokes the sandbox softly for information with your already configured SSH creds.

Fill in the variables at the top of the file or use commandline arguments.

How to get status:

python update_sandbox.py --user USER --sandbox meow.sandbox.meow.com

How to update:

python update_sandbox.py --user USER --sandbox meow.sandbox.meow.com --repo edx-platform --branch master
"""
import argparse
import paramiko
import requests

requests.packages.urllib3.disable_warnings()

SANDBOX = ""
LMS_URL = "https://{}".format(SANDBOX)
STUDIO_URL = "https://studio-{}".format(SANDBOX)
SSH_USERNAME = ""
BASIC_AUTH_CREDENTIALS = ("", "")
LMS_ENDPOINTS = [
    "",
    "login",
    "dashboard",
    "courses/course-v1:edX+DemoX+Demo_Course/info",
    "courses/course-v1:edX+DemoX+Demo_Course/discussion/forum",
    "courses/course-v1:edX+DemoX+Demo_Course/progress",
    "courses/v1/blocks/?course_id=course-v1%3AedX%2BDemoX%2BDemo_Course"
]
STUDIO_ENDPOINTS = [
    "",
    "course/course-v1:edX+DemoX+Demo_Course"
]
LMS_SERVER_VARS = [
    '"PREVENT_CONCURRENT_LOGINS": false',
    '"ENABLE_COURSE_BLOCKS_NAVIGATION_API": true'
]


class QA(object):

    def __init__(self):
        self.lms_url = LMS_URL
        self.studio_url = STUDIO_URL
        self.sess = requests.Session()
        self.sess.auth = ""

    def get_csrf(self, url):
        """
        return csrf token retrieved from the given url
        """
        try:
            response = self.sess.get(url)
            csrf = response.cookies['csrftoken']
            return {'X-CSRFToken': csrf, 'Referer': url}
        except Exception as error:  # pylint: disable=W0703
            print "Error when retrieving csrf token.", error

    def login_to_lms(self, email, password):
        """
        Use given credentials to login to lms.
        Args:
            email (str): Login email
            password (str): Login password
        """
        signin_url = '{}/login'.format(self.lms_url)
        headers = self.get_csrf(signin_url)
        login_url = '%s/login_ajax' % self.lms_url
        response = self.sess.post(login_url, {
            'email': email,
            'password': password,
            'honor_code': 'true'
        }, headers=headers).json()

        if not response['success']:
            raise Exception(str(response))

        print "***************LMS**************"

    def login_to_studio(self, email, password):
        """
        Use given credentials to login to studio.
        Attributes:
            email (str): Login email
            password (str): Login password
        """
        signin_url = '{}/signin'.format(self.studio_url)
        login_url = '{}/login_post'.format(self.studio_url)
        headers = self.get_csrf(signin_url)
        response = self.sess.post(
            login_url,
            data={
                'email': email,
                'password': password,
                'honor_code': 'true'
            },
            headers=headers).json()

        if not response['success']:
            raise Exception(str(response))
        print "*************STUDIO*************"

    def quality_check(self, email="staff@example.com", password="edx"):
        self.login_to_lms(email, password)
        errors = []
        for endpoint in LMS_ENDPOINTS:
            url = "{}/{}".format(self.lms_url, endpoint)
            response = self.sess.get(
                url=url
            )
            if response.status_code == 200:
                print "{}: {}".format(url, response.status_code)
            else:
                message = "{}: {}".format(url, response.status_code)
                errors.append(message)
                print message

        self.login_to_studio(email, password)
        for endpoint in STUDIO_ENDPOINTS:
            url = "{}/{}".format(self.studio_url, endpoint)
            response = self.sess.get(
                url=url
            )
            if response.status_code == 200:
                print "{}: {}".format(url, response.status_code)
            else:
                print "{}: {}".format(url, response.status_code)

    def check_basic_auth(self):
        print "*************BASIC AUTH*********************"
        url = "{}/courses".format(self.lms_url)
        response = self.sess.get(url)
        if response.status_code == 401 and response.headers.get("www-authenticate", "") == 'Basic realm="Restricted"':
            print "Basic Auth is ON for {}".format(url)
        else:
            print "Basic Auth is OFF for {}".format(url)

        url = "{}".format(self.lms_url)
        response = self.sess.get(url)
        if response.status_code == 401 and response.headers.get("www-authenticate", "") == 'Basic realm="Restricted"':
            print "Basic Auth is ON for {}".format(url)
        else:
            print "Basic Auth is OFF for {}".format(url)



        self.sess.auth = BASIC_AUTH_CREDENTIALS


class SshThings(object):

    def __init__(self, url, user):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.ssh.connect(url, username=user)

    def poke_sandbox(self):
        print "*************edx-platform*********************"
        stdin, stdout, stderr = self.ssh.exec_command("cd /edx/app/edxapp/edx-platform; git status")
        print stdout.read()
        stdin, stdout, stderr = self.ssh.exec_command("cd /edx/app/edxapp/edx-platform; git log -1")
        print stdout.read()
        print "***********cs_comments_service****************"
        stdin, stdout, stderr = self.ssh.exec_command("cd /edx/app/forum/cs_comments_service; git status")
        print stdout.read()
        stdin, stdout, stderr = self.ssh.exec_command("cd /edx/app/forum/cs_comments_service; git log -1")
        print stdout.read()

        print "************Sandbox Expiration****************"
        stdin, stdout, stderr = self.ssh.exec_command("python /edx/etc/playbooks/edx-east/roles/edx-sandbox/templates/etc/update-motd.d/temiate_motd.j2")
        print stdout.read()

    def update_sandbox(self, service, branch):
        print "Updating Sandbox... this can take a while"
        stdin, stdout, stderr = self.ssh.exec_command("sudo /edx/bin/update {} {}".format(service, branch))
        output = stdout.read()
        if "failed=0" in output:
            print "Update successful"
            print "Running Migrations"
            stdin, stdout, stderr = self.ssh.exec_command("cd /edx/app/edxapp/edx-platform; sudo -u www-data /edx/app/edxapp/venvs/edxapp/bin/python ./manage.py lms syncdb --migrate --settings aws")
            print "Restarting services"
            self.ssh.exec_command("sudo /edx/bin/supervisorctl restart edxapp_worker:")
            self.ssh.exec_command("sudo /edx/bin/supervisorctl restart edxapp:*")
            print "Servers restarted"


    def check_server_var(self, server_var, vars_to_check):
        print "**************{}*********************".format(server_var)
        stdin, stdout, stderr = self.ssh.exec_command("cat /edx/app/edxapp/{}".format(server_var))
        lms_server_vars = stdout.read()
        for server_item in vars_to_check:
            if server_item not in lms_server_vars:
                print "{} is not set".format(server_item)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--sandbox', help='Sandbox URL (without "https://")', default='')
    parser.add_argument('-u', '--user', help='User for sandbox', default='')
    parser.add_argument('-r', '--repo', help='Repository to update', default='')
    parser.add_argument('-b', '--branch', help='Branch to update with', default='')

    args = parser.parse_args()

    print ""
    sandbox_url = SANDBOX or args.sandbox or raw_input('Enter Sandbox URL (without "https://"): ')
    print "Sandbox url: " + sandbox_url
    username = SSH_USERNAME or args.user or raw_input('Enter User with SSH access: ')
    print "User for sandbox: " + username

    qa_user = QA()
    qa_user.check_basic_auth()
    qa_user.quality_check()

    ssh_thing = SshThings(sandbox_url, username)

    ssh_thing.update_sandbox(args.repo, args.branch)

    ssh_thing.poke_sandbox()

    ssh_thing.check_server_var("lms.env.json", LMS_SERVER_VARS)


if __name__ == "__main__":
    main()
