from subprocess import *
import requests
import time


class Cuckoo:
    def __init__(self, IP, PORT):
        self.CUCKOO_API_COMMAND = "cuckoo api"
        self.SUBMIT_FILE_URL = "http://"+IP+":"+str(PORT)+"/tasks/create/file"
        self.SUBMIT_URL_URL = "http://"+IP+":"+str(PORT)+"/tasks/create/url"
        self.SPECIFIC_TASK_VIEW_DETAILS_URL = "http://"+IP+":"+str(PORT)+"/tasks/view/"  # + id

        # JSON string full report
        self.SPECIFIC_TASK_VIEW_REPORT_URL = "http://"+IP+":"+str(PORT)+"/tasks/report/"  # + id
        self.END_CUCKOO_API =  "http://"+IP+":"+str(PORT)+"/exit"

    def run_cuckoo_api_cmd(self):
        # runs "cuckoo api" command
        # It prints to error pipe...
        p = Popen(self.CUCKOO_API_COMMAND, stderr=PIPE)
        print p.stderr.readline()

    def submit_file(self, path_to_file, timeout=30):
        # submit file to Cuckoo with path and timeout
        # returns task_id or -1
        task_id = None
        while task_id is None:
            name_of_file = self.getNameFile(path_to_file)
            with open(path_to_file, "rb") as sample:
                files = {"file": (name_of_file, sample)}
                data = {"timeout": timeout, "enforce_timeout": True}
                r = requests.post(self.SUBMIT_FILE_URL, files=files, data=data)
                if r.status_code == 200:
                    task_id = r.json()['task_id']
                    print self.getNameFile(path_to_file) + " submitted, given task_id = " + str(task_id)
                    if task_id is not None:
                        return task_id
                    else:
                        continue
                else:
                    print self.getNameFile(path_to_file) + " submission to Cuckoo failed."
                    return -1

    def submit_url(self, url, timeout=30):
        # submit URL to Cuckoo and timeout
        # returns task_id or -1
        task_id = None
        while task_id is not None:
            data = {"url": url, "timeout": timeout, "enforce_timeout": False}
            r = requests.post(self.SUBMIT_URL_URL, data=data)
            if r.status_code == 200:
                task_id = r.json()['task_id']
                print url + " submitted, given task_id = " + str(task_id)
                if task_id is not None:
                    return task_id
                else:
                    continue
            else:
                print url + " submission to Cuckoo failed."
                return -1

    def end_cuckoo_api(self):
        r = requests.get(self.END_CUCKOO_API)
        if r.status_code == 200:
            print "Cuckoo's API shut down"
        else:
            print "Shutting Cuckoo's API failed"

    def getNameFile(self, directory):
        # gets only file name of a long directory path
        parts = directory.split("\\")
        return parts[len(parts) - 1]

	# : target (file name or url), clock, category(file or url),
	#	completed_on (time completed), status(status of analysis: pending, completed, reported or running)
	# and duration (time taken by analysis)
    def get_task_status(self, task_id, print_bool=True):
        # given task id, it prints basic details of the task, status of report
        final_url = self.SPECIFIC_TASK_VIEW_DETAILS_URL + str(task_id)
        r = requests.get(final_url)
        if r.status_code == 200:
            task = r.json()["task"]
            if print_bool:
                print "-------------------------"
                print "Task Details for ID = " + str(task_id)
                print "Task: " + self.getNameFile(task["target"])
                print "Category: " + task["category"]
                print "Start Time: " + task["clock"]
                print "End Time: " + task["completed_on"]
                print "Status: " + task["status"]
                print "Duration: " + str(task["duration"]) + " seconds"
                print "-------------------------"
            return task["status"]
        else:
            if print_bool:
                print "Error: Couldn't find details of task " + str(task_id) + ", return code: " + str(r.status_code)
            return "NOT_FOUND"


    # #Category: file or url
    #Score: Cuckoo's score of severity
    #Duration: Time duration of cuckoo's operation
    #Status: Stopped, reported, pending or completed
    #Description: Cuckoo's noticed behaviour of the file/url
    #Severity: severity of a description
    #For files:
    #Sha-1,sha-256,sha-512,md5: hash functions
    #URLs: urls embedded in file
    #Type: type of file
    #DLL: dll file used by file
    #Pe_imports: functions used in that dll
    #Legalcopyright: A copyright if exists
    #Fileversion: version number of file.
    #Companyname: which company made this file
    #Comments: comments embedded in file
    #Productname: full product name
    #Productversion: formal version of product
    #FileDescription: description of a file
    #Translation: language of file
    def receive_report_task(self, task_id):
        # Given task_id, it prints full report of that task
        final_url = self.SPECIFIC_TASK_VIEW_REPORT_URL + str(task_id)
        r = requests.get(final_url)
        if r.status_code == 200:
            return r
        else :
            return -1

    def parse_report(self, r):
        task = r.json()["info"]
        print "-------------------------"
        print "Task Analysis Report "
        print "-------------------------"
        print "Category: " + task["category"]
        print "Cuckoo's score: " + str(task["score"])
        print "Package: " + task["package"]
        print "Duration: " + str(task["duration"])
        machine = task["machine"]
        print "Status: " + machine["status"]
        print "Started on: " + machine["started_on"]
        print "Shutdown on: " + machine["shutdown_on"]
        signatures = r.json()["signatures"]
        for index, value in enumerate(signatures):
            print "Description " + str(index + 1) + ": " + value["description"]
            print "Severity of description " + str(index + 1) + ": " + str(value["severity"])
        if task["category"] == "file":
            file_ = r.json()["target"]["file"]
            print "SHA-1: " + file_["sha1"]
            print "SHA-256: " + file_["sha256"]
            print "SHA-512: " + file_["sha512"]
            print 'MD5: ' + file_["md5"]
            urls = file_["urls"]
            for idx, url in enumerate(urls):
                print "URL " + str(idx + 1) + ": " + url
            print "Type: " + file_["type"]
            static = r.json()["static"]
            pe_imports = static["pe_imports"]
            print "----------------Imports-----------------"
            for idx_, item in enumerate(pe_imports):
                print "DLL " + str(idx_ + 1) + ": " + item["dll"]
                imports = item["imports"]
                for idx, val in enumerate(imports):
                    print "PE_Imports " + str(idx + 1) + ": " + val["name"]
                print "-----------------------------------------"
            print "-----------------------------------------"
            pe_version_info = static["pe_versioninfo"]
            print "-----------PE VERSION INFO---------------"
            for item in pe_version_info:
                print item["name"] + ": " + item["value"]
            print "-----------------------------------------"

    def analyze(self, file_path_or_url, file_bool, timeout_=30):
        # submit file or url, waits till cuckoo finishes and prints the report.
        try:
            timeout = timeout_
            additional_timeout = 30

            if file_bool:
                task_id = self.submit_file(file_path_or_url, timeout)
            else:
                task_id = self.submit_url(file_path_or_url, timeout)

            # print "Sleeping for " + str(timeout + additional_timeout) + " seconds until the operations are finished."
            time.sleep(timeout + additional_timeout)

            while self.get_task_status(task_id, False) != "reported":
                print "Report is not ready, sleeping for additional 5 seconds."
                time.sleep(5)

            if task_id != -1:
                return self.receive_report_task(task_id)
            return -1

        except Exception, e:
            print "do_main_operation exception"
            print e
