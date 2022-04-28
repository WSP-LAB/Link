#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2019 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import random
from itertools import chain
from os.path import join as path_join
from configparser import ConfigParser
from math import ceil
from requests.exceptions import ReadTimeout
from bs4 import Comment
from gym_reflected_xss.attack_module.attack.attack import Attack, Mutator, PayloadType, JSparser
from gym_reflected_xss.attack_module.language.vulnerability import Vulnerability, Anomaly
from gym_reflected_xss.attack_module.net.xss_utils import generate_payloads, valid_xss_content_type

from bs4 import BeautifulSoup
import re
import gym_reflected_xss.envs.observation as obs
import datetime
from difflib import SequenceMatcher
import difflib as dl
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
import chompjs
from pyjsparser import parse

class mod_xss(Attack):
    """This class implements a cross site scripting attack"""

    # magic strings we must see to be sure script is vulnerable to XSS
    # payloads must be created on those patterns
    script_ok = ["alert('__XSS__')", "alert(\"__XSS__\")", "String.fromCharCode(0,__XSS__,1)"]

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attribute value (attrval) or in the
    # content of a tag (text node like between <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []
    php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
    php_self_check = "<script>phpselfxss()</script>"

    name = "xss"

    # two dict exported for permanent XSS scanning
    # GET_XSS structure :
    # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
    # GET_XSS = {}
    # POST XSS structure :
    # {uniq_code: [target_url, {param1: val1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
    # POST_XSS = {}
    TRIED_XSS = {}
    PHP_SELF = []

    # key = taint code, value = (payload, flags)
    SUCCESSFUL_XSS = {}

    PAYLOADS_FILE = "xssPayloads.ini"

    MSG_VULN = ("XSS vulnerability")

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.independant_payloads = self.payloads
        self.current_state = [0] * obs.STATE_SIZE
        self.file = None
        self.file2 = None
        
        options = webdriver.ChromeOptions()
        options.add_argument('--headless')    # 웹 브라우저를 띄우지 않는 headless chrome 옵션 적용
        options.add_argument('--no-sandbox')  
        options.add_argument('--disable-dev-shm-usage') 
        
        self.driver = webdriver.Chrome(executable_path="/home/soyounglee/projects/gym-reflected-xss/chromedriver",options=options)
        
    

    @staticmethod
    def random_string():
        """Create a random unique ID that will be used to test injection."""
        # doesn't uppercase letters as BeautifulSoup make some data lowercase
        code = "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)])
        return code, set()

    def attack(self):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        mutator = Mutator(
            methods=methods,
            payloads=self.random_string,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, taint, flags in mutator.mutate(original_request):
                try:
                    # We don't display the mutated request here as the payload is not interesting
                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        # We just inserted harmless characters, if we get a timeout here, it's not interesting
                        continue
                    else:
                        # We keep a history of taint values we sent because in case of stored value, the taint code
                        # may be found in another webpage by the permanentxss module.
                        self.TRIED_XSS[taint] = (mutated_request, parameter, flags)

                        # Reminder: valid_xss_content_type is not called before before content is not necessary
                        # reflected here, may be found in another webpage so we have to inject tainted values
                        # even if the Content-Type seems uninteresting.
                        if taint.lower() in response.content.lower() and valid_xss_content_type(mutated_request):
                            # Simple text injection worked in HTML response, let's try with JS code
                            payloads = generate_payloads(response.content, taint, self.independant_payloads)

                            # TODO: check that and make it better
                            if PayloadType.get in flags:
                                method = "G"
                            elif PayloadType.file in flags:
                                method = "F"
                            else:
                                method = "P"

                            # self.attempt_exploit(method, payloads, original_request, parameter, taint)
                except KeyboardInterrupt as exception:
                    yield exception

            yield original_request

    @property
    def payloads(self):
        """Load the payloads from the specified file"""
        if not self.PAYLOADS_FILE:
            return []

        payloads = []
        """
        config_reader = ConfigParser(interpolation=None)
        config_reader.read_file(open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE)))

        for section in config_reader.sections():
            payload = config_reader[section]["payload"]
            flags = {section}

            clean_payload = payload.strip(" \n")
            clean_payload = clean_payload.replace("[TAB]", "\t")
            clean_payload = clean_payload.replace("[LF]", "\n")
            clean_payload = clean_payload.replace(
                "[TIME]",
                str(int(ceil(self.options["timeout"])) + 1)
            )

            payload_type = PayloadType.pattern
            if "[TIMEOUT]" in clean_payload:
                payload_type = PayloadType.time
                clean_payload = clean_payload.replace("[TIMEOUT]", "")

            flags.add(payload_type)
            payloads.append((clean_payload, flags))
        """
        return payloads

    def find_injection_point(self, method, payloads, original_request, parameter, taint, input_module, paramType):
        result_state = [0, 0, 0, 0, 0, 0, 0, 0]
        onmouseover_list = ["img", "video", "svg", "input", "textarea", "a","form"]
        params = []
        if method == "G":
            params = original_request.get_params
        elif method == "P":
            params = original_request.post_params
        
        default_value = ""
        if params:
            for p in params:
                if p[0] == parameter:
                    default_value = p[1]
                    break
        
        """ default value type
        1: number
        2: string

        """
        if default_value:
            if default_value.isnumeric():
                result_state[4] = 1
            
            else:
                result_state[4] = 2
            
    

        attack_mutator = Mutator(
            methods=method,
            payloads=payloads,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )
        try: 
            if paramType == 1:
                evil_request, xss_param, xss_payload, xss_flags = attack_mutator.refererMutate(original_request)
            elif paramType == 2:
                evil_request, xss_param, xss_payload, xss_flags = attack_mutator.urlMutate(original_request)
            else:
                evil_request, xss_param, xss_payload, xss_flags = next(attack_mutator.mutate(original_request))
        except StopIteration:
            print("nothing")
            return result_state
        else:
            try:
                response = self.crawler.send(evil_request)
            except:
                return result_state
        
        
        # print(response._response.text)
        if (response.status == 404 or response.status == 500) and paramType == 2:
            return result_state
        
        payload_string = payloads[0]

        """ status
        1. content type
            0: default
            1: HTML context
            2: CSS context
            3: JSON
        """

        

        response_content = response._response.text.replace(" ", "").replace("\n","")
        # content type inference 
        result_state[0] = 1
        if response.soup.find("html") != None or "html" in original_request.url :
            result_state[0] = 1
        elif response.soup.find("style") != None:
            result_state[0] = 2
        elif len(response_content) > 0 and response_content[0] == "{":
            result_state[0] = 3
        # delete all space in html content

        #original_content = response._response.text
        original_content = response._response.text
        # find efficient tag for payload generation
        indexPayload = original_content.find(payload_string)
        if indexPayload > 0:
            result_state[3] = 1
        elif original_content.find(payload_string[1:len(payload_string)-2]) > 0:
            result_state[3] = 1
        
        sliced_original_content = original_content
        while indexPayload > 0:
            previous_list = result_state.copy()
            #print(indexPayload)
            """ find escaping character
                \": 1
                \': 2
                / : 3
                * : 4
                < : 5
                > : 6
                -: 7
            """
            previous_result = result_state[5]
            for i in range(indexPayload-1, 0, -1):
                #print(sliced_original_content[i])
                special_character_l = re.findall(r'\*|\/|\'|\"|\>|\<|\-',sliced_original_content[i])
                if len(special_character_l) > 0:
                    special_character = special_character_l[0]
                    
                    
                    if special_character == "'":
                        result_state[5] = 1
                        break
                    elif special_character == '"':
                        result_state[5] = 2
                        break
                    elif special_character == "/":
                        result_state[5] = 3
                        if sliced_original_content[i-1] == "/" and sliced_original_content[i-2] != ":":
                            break
                        
                    elif special_character =="*":
                        result_state[5] = 4
                        if sliced_original_content[i-1] == "/":
                            break
                        
                    elif special_character == "<":
                        result_state[5] = 5
                        
                    elif special_character == ">":
                        result_state[5] = 6
                        break
                    elif special_character == "-":
                        result_state[5] = 7
            
            if previous_result < result_state[5] and previous_result > 0:
                result_state[5] = previous_result

            last_tag = ""
            # find enter character in injection line
            finalIndex = sliced_original_content[indexPayload+len(payload_string):].find('>')
            if indexPayload != -1:
                
                # find right before tag it need to contain enough string contain bracket >
                if finalIndex != -1:
                    sliced_content = sliced_original_content[0:(indexPayload + len(payload_string) +finalIndex + 1)]
                else:
                    sliced_content = sliced_original_content[0:(indexPayload + len(payload_string) +4)]

                payload_soup = BeautifulSoup(sliced_content, 'html.parser')
                tag_list = payload_soup.find_all()

                
                if len(tag_list) > 0:
                    last_tag = tag_list[-1].name
                    input_module.effective_tag.append(last_tag)
                    # EFFECTIVE_TAG_TYPE
                    if last_tag in onmouseover_list:
                        result_state[7] = 1
                    elif last_tag.strip() == "script":
                        result_state[7] = 2
                print("founded tag: " + str(last_tag))
            
            """ 
            3. what is before injection payload
                0: default
                1: single quotation
                2: double quotation
                3: bracket
                4: equal
                5: colon
                6: semicolon
                7: alphabet
                8: number
            """
            response_content1 = sliced_original_content.replace(" ", "").replace("\n","")
            indexPayload1 = response_content1.find(payload_string)
            #print(response_content)
            #print(payload_string)
            #print("index: " + str(indexPayload))
            previous_result = result_state[2]
            previous_result_after =  result_state[6]
            if indexPayload1 > 0:
                before_str = response_content1[indexPayload1 - 1] 
                after_str=""
                try:
                    after_str = response_content1[indexPayload1 + len(payload_string)] 
                except IndexError:
                    pass
                if before_str == "'":
                    result_state[2] = 1
                elif before_str == '"':
                    result_state[2] = 2
                elif before_str == ">":
                    result_state[2] = 3
                elif before_str == "=":
                    result_state[2] = 4
                elif before_str == ":":
                    result_state[2] = 5
                elif before_str == ";":
                    result_state[2] = 6
                """
                elif re.search('[a-zA-Z]', before_str) != None:
                    result_state[2] = 7
                elif re.search('[0-9]', before_str) != None:
                    result_state[2] = 8
                """
                if after_str == "'":
                    result_state[6] = 1
                elif after_str  == '"':
                    result_state[6] = 2
                elif after_str  == ">":
                    result_state[6] = 3
                elif after_str == "=":
                    result_state[6] = 4
                elif after_str  == ":":
                    result_state[6] = 5
                elif after_str  == ";":
                    result_state[6] = 6
                """
                elif re.search('[a-zA-Z]', after_str) != None:
                    result_state[6] = 7
                elif re.search('[0-9]', after_str) != None:
                    result_state[6] = 8
                """
            
                
            #if previous_result_after < result_state[6] and previous_result_after != 0:
            #    result_state[6] = previous_result_after
            
            
        
            """
            2. Injection point information
                0: default
                1: tag name
                2: html attribute name
                3: url
                4: comment
                5: value
                6: context in html tag <tag>inejection string</tag>
                7: event
                8: javascript
            """
            previous_result = result_state[1] 

            
            
            # tag name
            if response.soup.find(payload_string) != None:
                result_state[1] = 1
            
            
            # attribute name
            tags = response.soup.find_all()
            for t in tags:
                try:
                    if t[payload_string] != None:
                        result_state[1] = 2
                        print(t)
                except KeyError:
                    pass

            
            # url
            links = response.soup.find_all("a")
            for a in links:
                try:
                    href = a.attrs['href']
                    if payload_string in href:
                        result_state[1] = 3
                            
                except KeyError:
                    pass
                  
            src_list = ["href", "src", "data", "action", "value"]
            if last_tag != "":    
                for tag in response.soup.find_all(last_tag):
                    #TODO
                    #print(tag)
                    #print(payload_string)
                    for e in src_list: 
                        try:
                            if payload_string in tag[e]:
                                result_state[1] = 3
                                if "javascript:" in tag[e]:
                                    result_state[1] = 8
                        except KeyError:
                                pass    
            
            if result_state[1] == 0:
                # comment
                comments = response.soup.find_all(string=lambda text: isinstance(text, Comment))
                for c in comments:
                    if payload_string in c:
                        result_state[1] = 4
                
            
            if result_state[1] == 0 and indexPayload1 != -1:
                # value
                if response_content1[indexPayload1 - 1] == '=' or  response_content1[indexPayload1 - 1] == '"' or response_content1[indexPayload1 - 1] == "'":
                    result_state[1] = 5
                
            # context
            for tag in response.soup.find_all(last_tag): 
                #print(tag.string)
                if tag.string!= None and payload_string in tag.string:
                    result_state[1] = 6


            event_list = ["onClick","onclick", "onerror", "onmouseover","onload"]
            if last_tag != "":    
                for tag in response.soup.find_all(last_tag):
                    #TODO
                    for e in event_list: 
                        try:
                            if payload_string in tag[e]:
                                result_state[1] = 7
                        except KeyError:
                                pass    
            previous = False
           
            if (previous_result < result_state[1]) and previous_result != 0:
                previous = True
            if previous:
                result_state = previous_list.copy()
            #print(result_state)
            sliced_original_content =sliced_original_content[indexPayload+len(payload_string):]
            indexPayload =sliced_original_content.find(payload_string) 
                 

        return result_state

    def attempt_exploit(self, method, payloads, original_request, parameter, taint, input_module, paramType=0):
        
        # logger
        self.file.write("payload: " + str(payloads) + "\n")
        self.file.write("request: " + str(original_request)+ "\n")
        timeouted = False
        page = original_request.path
        saw_internal_error = False
        
        attack_mutator = Mutator(
            methods=method,
            payloads=payloads,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )
        
        # print("referer: " + str(original_request.referer))
        if paramType == 1:
            evil_request, xss_param, xss_payload, xss_flags = attack_mutator.refererMutate(original_request)
            # print("referer mutate: " + evil_request.referer)
        elif paramType == 2:
            evil_request, xss_param, xss_payload, xss_flags = attack_mutator.urlMutate(original_request)
        else:
            evil_request, xss_param, xss_payload, xss_flags = next(attack_mutator.mutate(original_request))
            # print("normal mutate: " + evil_request.referer)
        # logger
        self.file.write("evil_request: " + str(evil_request) + "\n")
        self.file.write("referer: " + evil_request.referer+ "\n")
        if self.verbose == 2:
                print("[¨] {0}".format(evil_request))

        try:
            response = self.crawler.send(evil_request)
            """if paramType:
                print(response._response.text)"""
            #self.file.write("response: " + str(response.status) + "\n")
        except ReadTimeout:
            

            self.log_orange("---")
            self.log_orange(Anomaly.MSG_TIMEOUT, page)
            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
            self.log_orange(evil_request.http_repr())
            self.log_orange("---")

            if xss_param == "QUERY_STRING":
                anom_msg = Anomaly.MSG_QS_TIMEOUT
            else:
                anom_msg = Anomaly.MSG_PARAM_TIMEOUT.format(xss_param)

            self.add_anom(
                request_id=original_request.path_id,
                category=Anomaly.RES_CONSUMPTION,
                level=Anomaly.MEDIUM_LEVEL,
                request=evil_request,
                info=anom_msg,
                parameter=xss_param
            )
            timeouted = True
            attack_success = False 
            

            status = input_module.status
            
        else:
            attack_success, status = self.check_payload(response, taint, xss_flags, xss_payload, input_module)
            """
            if string_rate > 0:
                print("---- vulnerability detection ----")
                print("evil request: " + str(evil_request))
                print("xss_param: " + str(xss_param))
            """
            if attack_success:
                
                self.SUCCESSFUL_XSS[taint] = (xss_payload, xss_flags)
                self.add_vuln(
                    request_id=original_request.path_id,
                    category=Vulnerability.XSS,
                    level=Vulnerability.HIGH_LEVEL,
                    request=evil_request,
                    parameter=xss_param,
                    info=("XSS vulnerability found via injection"
                           " in the parameter {0}").format(xss_param)
                )
                # logger
                self.file.write("\n\n---- vulnerability detection ----\n")
                if(len(str(evil_request)) < 500):
                    self.file.write("evil request: " + str(evil_request) + "\n")
                self.file.write("xss_param: " + str(xss_param) + "\n\n")
                
                # detection file logger
                #self.file2.write("\n\n--------------------------------------------------------\n")
                # self.file2.write(("XSS vulnerability found via injection" " in the parameter {0}").format(xss_param) + "\n")
                #self.file2.write("evil request: " + str(evil_request) + "\n")
                #self.file2.write("xss_param: " + str(xss_param) + "\n\n")
                #self.file2.write("--------------------------------------------------------")
                #self.file2.write("\n\n---- vulnerability detection ----\n")
                #self.file2.write("detection time: " + str(datetime.datetime.now()) + "\n")
                #self.file2.write("evil request: " + str(evil_request) + "\n")
                #self.file2.write("xss_param: " + str(xss_param) + "\n")
                self.file2.write(original_request.url)
                self.file2.write("\n")
                #self.file2.write("\n--------------------------------------------------------")
                #self.file2.write("\n")
                if xss_param == "QUERY_STRING":
                    injection_msg = Vulnerability.MSG_QS_INJECT
                else:
                    injection_msg = Vulnerability.MSG_PARAM_INJECT

                self.log_red("---")
                self.log_red(
                    injection_msg,
                    self.MSG_VULN,
                    page,
                    xss_param
                )
                self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                if(len(str(evil_request)) < 500):
                    self.log_red(evil_request.http_repr())
                self.log_red("---")

            #elif response.status == 302:
                #self.crawler.login()  
            elif response.status == 500 and not saw_internal_error:
                
                if xss_param == "QUERY_STRING":
                    anom_msg = Anomaly.MSG_QS_500
                else:
                    anom_msg = Anomaly.MSG_PARAM_500.format(xss_param)
                """
                self.add_anom(
                    request_id=original_request.path_id,
                    category=Anomaly.ERROR_500,
                    level=Anomaly.HIGH_LEVEL,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param
                )

                self.log_orange("---")
                self.log_orange(Anomaly.MSG_500, page)
                self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                self.log_orange(evil_request.http_repr())
                self.log_orange("---")
                saw_internal_error = True  
                """
        return attack_success, status

    """ 

    State of output in response payload

    ATTACK_SUCCESS = 0
    INVALID_INPUT_REJECT = 1
    FILTER_SCRIPT_TAG = 2 
    FILTER_HTML_TAG = 3
    FILTER_BRACKETS = 4
    FILTER_QUOTATION = 5
    FILTER_BACKSLASH = 6
    INJECTED_NOT_EXECUTED = 7
    STRING_INJECTED = 8

    """
    # send all random strings for all parameters, return parameter list that reflect something
    def filter_injection_points(self, original_request):
        reflect_list = []

        # payload with only string and number
        if original_request.method == "GET":
            method = "GET"
            params = original_request.get_params
        elif original_request.method == "POST":
            method = "POST"
            params = original_request.post_params
        
        attack_mutator = Mutator(
            methods=method,
            parameters=params,
            skip=self.options.get("skipped_parameters")
        )

        try: 
            evil_request, xss_payload = attack_mutator.allMutate(original_request)
            #self.file.write("attack time: " + str(datetime.datetime.now()) + "\n")
            #self.file.write("evil_request: " + str(evil_request) + "\n")
            #self.file.write("referer: " + evil_request.referer+ "\n")
        except StopIteration:
            print("nothing")
        else:
            response = self.crawler.send(evil_request)

      
        response_content = response._response.text
        for i in range(len(xss_payload)):
            payload_string = "injection" + str(i) + "here"

            if response_content.find(payload_string) > -1:
                reflect_list.append(xss_payload[i][0])
            elif response_content.find(payload_string[1:len(payload_string)-2]) > -1:
                reflect_list.append(xss_payload[i][0])

        payload_string = "injection" + str(len(xss_payload)) + "here"
        
        if response_content.find(payload_string) > -1:
   
            reflect_list.append("refererHeader")
        elif response_content.find(payload_string[1:len(payload_string)-2]) > -1:
            reflect_list.append("refererHeader")

        # payload with characters
        reflect_list2 = []
        if len(params) != len(reflect_list):
        
            try: 
                #self.file.write("attack time: " + str(datetime.datetime.now()) + "\n")
                evil_request, xss_payload = attack_mutator.allMutateWithChar(original_request)
                #self.file.write("evil_request: " + str(evil_request) + "\n")
                #self.file.write("referer: " + evil_request.referer+ "\n")
            except StopIteration:
                print("nothing")
            else:
                response = self.crawler.send(evil_request)

            response_content = response._response.text
            for i in range(len(xss_payload)):
                payload_string = "injection" + str(i) + "here"

                if response_content.find(payload_string) > 0:
                    reflect_list2.append(xss_payload[i][0])
                elif response_content.find(payload_string[1:len(payload_string)-2]) > 0:
                    reflect_list2.append(xss_payload[i][0])

            payload_string = "injection" + str(len(xss_payload)) + "here"
            if response_content.find(payload_string) > 0:
                reflect_list2.append("refererHeader")
            elif response_content.find(payload_string[1:len(payload_string)-2]) > 0:
                reflect_list2.append("refererHeader")
        
        result_list = list(set(reflect_list) | set(reflect_list2))
        return result_list

    def check_payload(self, response, taint, flags, payload, input_module):
        
        attack_success = False 
        input_module.status[obs.TAG_INJECTED] = 0
        input_module.status[obs.STRING_INJECTED] = -1
        input_module.status[obs.ATTACK_SUCCESS] = 0
        input_module.status[obs.SIMILARITY] = 0
        attribute = input_module.attribute
        value = input_module.value
        event = input_module.event
        

        # test headless browser overhead
        """
        try:
            
            content = response._response.text
            
            self.driver.get("data:text/html;charset=utf-8," + content)

        except:
            pass
        """
        soup_page = ""
        if(len(payload) == 0) :
            input_module.status[obs.TAG_INJECTED] = 0
            input_module.status[obs.STRING_INJECTED] = -1
            input_module.status[obs.ATTACK_SUCCESS] = 0
            input_module.status[obs.SIMILARITY] = 0
            return attack_success, input_module.status


        if input_module.status[obs.HEXA_ENCODING]:
            # status 0: attack success 
            try:
                """
                options = webdriver.ChromeOptions()
                options.add_argument('--headless')    # 웹 브라우저를 띄우지 않는 headless chrome 옵션 적용
                options.add_argument('--no-sandbox')  
                options.add_argument('--disable-dev-shm-usage') 
                """
                content = response._response.text
                #self.driver = webdriver.Chrome(executable_path="/home/soyounglee/projects/gym-reflected-xss/chromedriver",options=options)
                self.driver.get("data:text/html;charset=utf-8," + content)
                try:
                    alert = self.driver.switch_to_alert()
                    if alert:
                        alert.accept()
                except:
                    pass
                soup_page = self.driver.page_source
            except:
                soup_page =response._response.text
        else:
            soup_page =response._response.text
        
        #print(soup_page)
        
        soup = BeautifulSoup(soup_page, 'html5lib')
        tag = []
        
        if input_module.status[obs.TAG_INSERTED] == 1:
            tag = soup.find_all(input_module.original_tag)
        elif input_module.tag != "": 
            tag = soup.find_all(input_module.tag)
            if tag == []:
                tag = soup.find_all(input_module.tag.lower())

        # logger
        #self.file.write("tag: " + str(tag)+ '\n')
        
        # noscript handler -> noscript 내부의 script는 실행되지 않음
        noscript = False
        if soup.find("noscript"):
            # soup2 = BeautifulSoup(response._response.text, 'html.parser')

            list_contents = soup.find("noscript").contents
            
            for c in list_contents:
                
                if c.name == input_module.tag or c.name == input_module.original_tag:
                    if attribute == "string" and c.string:
                        if (value.lower() in c.string.lower()) or (c.string.lower() in value.lower())  :
                            attack_success = False
                            input_module.status[obs.STRING_INJECTED] = 1
                            input_module.status[obs.ATTACK_SUCCESS] = 0
                            noscript = True
                    elif event in c.attrs:
                        if (value.lower() in c[event].lower()) or (c[event].lower() in value.lower()) :
                            attack_success = False
                            input_module.status[obs.STRING_INJECTED] = 1
                            input_module.status[obs.ATTACK_SUCCESS] = 0
                            noscript = True


        if len(tag) > 0 and noscript == False:
            input_module.status[obs.TAG_INJECTED] = 1
            for t in tag:
                #print(event)
                if attribute == "string" and t.string:
                    #self.file.write("string: " + str(t.string)+ '\n')
                    if value.lower() == t.string.lower():
                        attack_success = True 
                        input_module.status[obs.STRING_INJECTED] = 1
                        input_module.status[obs.ATTACK_SUCCESS] = 1
                        break
                
                elif event in t.attrs:
                    #self.file.write("event: " + str(t[event].lower())+ '\n')
                    #self.file.write(value.lower())
                    #self.file.write('\n')
                    #self.file.write(t[event].lower())
                    #self.file.write('\n')
                    
                    stripped_value = value.lower().strip().replace("/","").replace(";","").replace(" ", "").replace("'","").replace('"',"")
                    if (stripped_value in t[event].lower()) or (t[event].lower() in stripped_value) :
                        attack_success = True 
                        input_module.status[obs.STRING_INJECTED] = 1
                        input_module.status[obs.ATTACK_SUCCESS] = 1
                        break

                elif attribute in t.attrs:
                    #self.file.write("attribute: " + str(t[attribute].lower())+ '\n')
                    if (value.lower() == t[attribute].lower()):
                        attack_success = True 
                        input_module.status[obs.STRING_INJECTED] = 1
                        input_module.status[obs.ATTACK_SUCCESS] = 1
                        break


        elif input_module.tag != "" and len(tag) == 0:  
            
            input_module.status[obs.TAG_INJECTED] = -1
            
            str_response = response._response.text

            # tag는 짤리고 value만 inejction
            if str_response.find(value)  > 0:
                input_module.status[obs.STRING_INJECTED] = 1
                
       
        elif input_module.tag == "" and len(payload) > 0: # using value injection payload not whole html payload
            
            # print("effectivetag: " + str(input_module.effective_tag))
            #TODO
            event_list =["onClick", "onclick", "onerror", "onmouseover", "onload"]
            src_list = ["href", "src", "data", "action", "value"]
            onmouseover_list = ["img", "video", "svg", "input", "textarea", "a","form"]
            load_list = ["a", "img", "video", "svg", "script", "audio", "iframe", "link", "style", "object", "param", "form", "base", "frame"]
            effective_tag_list = []
            for tag in input_module.effective_tag:
                effective_tag_list = effective_tag_list + soup.find_all(tag)
            for contain_tag in effective_tag_list:
                if attack_success:
                    break
                if input_module.status[obs.JS_PAYLOAD] == 1:

                    for e in event_list:
                        
                        try:
                            stripped_value = value.lower().strip().replace("/","").replace(";","").replace(" ", "").replace("'","").replace('"',"")
                            if stripped_value in contain_tag[e]:

                                # if payload such as src=x onerror="alert(1)" -> real exploit need src=x too
                                if input_module.status[obs.EVENT_ELEMENT] == 1:
                                    try:
                                        if e == "onmouseover" and contain_tag.name in onmouseover_list:
                                            attack_success = True
                                            input_module.status[obs.STRING_INJECTED] = 1
                                            input_module.status[obs.ATTACK_SUCCESS] = 1
                                        elif "x" in contain_tag["src"]: 
                                            attack_success = True
                                            input_module.status[obs.STRING_INJECTED] = 1
                                            input_module.status[obs.ATTACK_SUCCESS] = 1
                                           
                                        else:
                                            input_module.status[obs.STRING_INJECTED] = 1
                                            input_module.status[obs.ATTACK_SUCCESS] = 0
                                        
                                          
                                    except KeyError:
                                        try:
                                            if e == "onmouseover" and contain_tag.name in onmouseover_list:
                                                attack_success = True
                                                input_module.status[obs.STRING_INJECTED] = 1
                                                input_module.status[obs.ATTACK_SUCCESS] = 1
                                            elif "x" in contain_tag["SRC"]:
                                                attack_success = True
                                                input_module.status[obs.STRING_INJECTED] = 1
                                                input_module.status[obs.ATTACK_SUCCESS] = 1
                                      
                                            else:
                                                input_module.status[obs.STRING_INJECTED] = 1
                                                input_module.status[obs.ATTACK_SUCCESS] = 0
                                            
                                        except KeyError:
                                            input_module.status[obs.STRING_INJECTED] = 1
                                            input_module.status[obs.ATTACK_SUCCESS] = 0
                                else:
                                    attack_success = True
                                    input_module.status[obs.STRING_INJECTED] = 1
                                    input_module.status[obs.ATTACK_SUCCESS] = 1
                        except KeyError:
                            pass
                    for e in src_list:
                        if not (contain_tag.name == "input" and e == "value"):
                            try:
                                
                                if value in contain_tag[e] and "javascript:" in contain_tag[e]:
                                     #TODO
                                    jsparser = JSparser()
                                    
                                    if jsparser.jsparse(contain_tag[e].split("javascript:")[1]):
                                        attack_success = True
                                        input_module.status[obs.ATTACK_SUCCESS] = 1
                                    input_module.status[obs.STRING_INJECTED] = 1
                                    
                            except KeyError:
                                pass
                elif input_module.status[obs.JAVASCRIPT_FILE_NAME] == 1 or input_module.status[obs.URL_PAYLOAD] == 1:

                    for e in src_list:
                        if not (contain_tag.name == "input" and e == "value") and contain_tag.name in load_list:
                            try:
                                
                                if value == contain_tag[e]:
                                    attack_success = True
                                    
                                    input_module.status[obs.STRING_INJECTED] = 1
                                    input_module.status[obs.ATTACK_SUCCESS] = 1
                            except KeyError:
                                pass
                elif input_module.status[obs.JAVASCRIPT_CODE] == 1:
                    for e in event_list:
                        try:
                            
                            if value in contain_tag[e]:
                                #TODO
                                jsparser = JSparser()
                                if jsparser.jsparse(contain_tag[e]):
                                    attack_success = True
                                    input_module.status[obs.ATTACK_SUCCESS] = 1
                                input_module.status[obs.STRING_INJECTED] = 1
                                
                        except KeyError:
                            pass
                    for e in src_list:
                        if not (contain_tag.name == "input" and e == "value") and input_module[obs.EVENT_ELEMENT] != 1:
                            try:
                                
                                if value in contain_tag[e] and "javascript" in contain_tag[e]:
                                    #TODO
                                    jsparser = JSparser()
                                    if jsparser.jsparse(contain_tag[e].split("javascript:")[1]):
                                        attack_success = True
                                        input_module.status[obs.ATTACK_SUCCESS] = 1
                                
                                    input_module.status[obs.STRING_INJECTED] = 1
                                    
                            except KeyError:
                                pass
            
            if not attack_success and input_module.status[obs.JAVASCRIPT_CODE] == 1 and input_module.status[obs.EVENT_ELEMENT] == 0:
                for contain_tag in soup.find_all("script"):
                    stripped_value = value.lower().strip().replace("/","").replace(";","").replace(" ", "").replace("'","").replace('"',"")
                    # TODO
                    if contain_tag.string!=None and stripped_value in contain_tag.string:
                        #objects = parse(contain_tag.string)
                        #print(objects)
                        jsparser = JSparser()
                        if jsparser.jsparse(contain_tag.string):
                            attack_success = True
                            input_module.status[obs.ATTACK_SUCCESS] = 1
                        input_module.status[obs.STRING_INJECTED] = 1
            
         
        # original tag 가 아닌 inejcted tag로 injection이 성공한 경우 -> attack fail
        if input_module.original_tag != "" and soup.find(input_module.tag):
            attack_success = False
            input_module.status[obs.ATTACK_SUCCESS] = 0

        if input_module.status[obs.CODE_OBSFUSCATION] == 1:
            for contain_tag in soup.find_all("script"):
                if contain_tag.string!=None and input_module.current_input != "" and input_module.current_input in contain_tag.string :
                    attack_success = True
                    input_module.status[obs.STRING_INJECTED] = 1
                    input_module.status[obs.ATTACK_SUCCESS] = 1
        

        if not attack_success and not noscript and len(payload) > 5 and input_module.tag != "":
            str_response = response._response.text

            # response contain whole payload string
            if input_module.original_tag != "":
                payload2 = payload.replace(input_module.original_tag,"")
            else:
                payload2 = payload
            if str_response.find(payload2)  > 0:
                #self.file.write("not executed: " + payload2 + '\n')
                # status 7: INJECTED_NOT_EXECUTED
                input_module.status[obs.TAG_INJECTED] = 1
                input_module.status[obs.STRING_INJECTED] = 1
            
                
        elif input_module.tag == "" and not attack_success and not noscript:
            str_response = response._response.text  
            # only string is injected / partial injected
            
            if str_response.find(payload)  >= 0 or str_response.find(payload[1:len(payload)-2])>= 0:   
                 
                input_module.status[obs.STRING_INJECTED] = 1
            
                
            """
            # response contain value string
            else:
                if str_response.find(value) > 0:
                    input_module.status[obs.VALUE_INJECTED] = 1

                # response contain tag string
                if str_response.find(input_module.tag) > 0:
                    input_module.status[obs.TAG_INJECTED] = 1
            """
        

        # similarity between generated input and response output
        str_response = response._response.text
        start_index = str_response.find(input_module.random_tag)
        if start_index > 0 and len(payload) > 5:
            response_output = str_response[start_index - len(payload):start_index]
            similarty = SequenceMatcher(None, response_output[5:], payload[5:]).ratio()
            input_module.status[obs.SIMILARITY] = similarty * 5
        
        else:
            input_module.status[obs.SIMILARITY] = 0
        return attack_success, input_module.status
