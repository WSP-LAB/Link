import gym
from urllib.parse import urlparse
from gym import error, spaces, utils
from gym.utils import seeding

import sys
from enum import Enum
from importlib import import_module
from operator import attrgetter
from itertools import chain
from requests.exceptions import RequestException, ReadTimeout
from colorama import Fore, Back, Style
import numpy as np 
import pandas as pd 
from random import * 
import copy
import matplotlib.pyplot as plt 
from matplotlib.offsetbox import TextArea
import datetime
import csv
# from gym_reflected_xss.attack_module.language.language import _
from gym_reflected_xss.attack_module.main.attack_module import AttackModule, InvalidOptionValue
from gym_reflected_xss.input_module.input_generator import InputGenerator
from gym_reflected_xss.attack_module.language.logger import ConsoleLogger
from gym_reflected_xss.attack_module.attack.attack import Attack, Mutator, PayloadType
from gym_reflected_xss.attack_module.net.xss_utils import generate_payloads, valid_xss_content_type
import gym_reflected_xss.envs.observation as obs
import gym_reflected_xss.envs.action as act



class ReflectedXSSEnv(gym.Env):
   

    def __init__(self, start_url="http://localhost:1234/", mode=0, log_file_name="train_log.txt", block_obs=-1):
        self.mode = mode # 0: training mode 1: attack mode
        self.f = open(log_file_name, 'w')
        #self.f = None
        self.f2 = open("vul_detection", 'w')
        #self.f2 = None
        #self.f3 = open("cdf","w")
        self.block_list_file = open("url_block_list.txt","r")
        print(start_url)
        self.root_url = start_url
        self.attack_module = AttackModule(self.root_url)
        
        self.input_module = InputGenerator()
        
        self.max_try = 30
        self.block_obs = block_obs

        self.action_size = act.ACTION_SIZE
        self.action_space = spaces.Discrete(self.action_size)

        self.state_size = obs.STATE_SIZE
        self.observation_space = spaces.Box(low=-1.0, high=float(self.max_try + 1), shape=(self.state_size,), dtype=np.float32)
        self.initial_status = np.array([0.0] * self.state_size)
        self._observation = np.array([0.0] * self.state_size)
        
        # step counter for 1 episode
        self._envStepCounter = 0

        # step & vul couter for total episode
        self.numVulCounter = 0
        self.totalStepCounter = 0
        """self.action_dict = {}
        for i in range(self.action_size):
            self.action_dict[str(i)] = 0 """
        
        self.action =  -1

        self.num_steps_list = [0, 0, 0, 0, 0, 0, 0, 0]

        self.injection_state = [0, 0, 0]

        self.url_block_list = []
        for line in self.block_list_file:

            self.url_block_list.append(line.strip().replace('\n',""))
        #print(self.url_block_list)
       
        self.setup_attack()
        self.current_original_request = None
        self.attacked = {}
        
       
        self.removeInjectionTarget = False
        self.current_injection_points = None
        # self.find_vul 0: not found url, 1: found injection point, but not vul, 2: find vul
        self.find_vul = 0
        self.parameter = []
        # parameter type 0: parameter, 1: referer, 2: url
        self.paramType = 0
        self.attack_parameter_list = None
        self.request_list_index = 0
        
        self.try_list_url = []
        self.try_list_referer = []


    # wapiti main function
    def setup_attack(self):
    
        start_url = self.root_url
        """
        parts = urlparse(start_url)
        if not parts.scheme or not parts.netloc or not parts.path:
            print(("Invalid base URL was specified, please give a complete URL with protocol scheme"
                    " and slash after the domain name."))
            exit()
        """
        try:
            if start_url.startswith(("http://", "https://")):
                if start_url == "https://localhost:8443/benchmark/":
                    url_file = open("burp-owasp-urls.txt")
                    while True:
                        line = url_file.readline().replace("\n", '').replace(" ", '')
                        print(line)
                        if not line: break
                        self.attack_module.add_start_url(line)
                    url_file.close()
                
                else:
                    self.attack_module.add_start_url(start_url)
            
                 
            self.attack_module.set_max_depth(40)
            self.attack_module.set_max_files_per_dir(0)
            self.attack_module.set_max_links_per_page(0)
            self.attack_module.set_scan_force("normal")
            self.attack_module.set_max_scan_time(0)

            # should be a setter
            self.attack_module.verbosity(0)
            self.attack_module.set_timeout(6.0)
            self.attack_module.set_modules(None)

            self.attack_module.set_verify_ssl(bool(0))

            attack_options = {
                "level": 1,
                "timeout": 6.0
            }

            self.attack_module.set_attack_options(attack_options)
            # reset crawler 
            self.attack_module.flush_attacks()
            self.attack_module.flush_session()
            #self.f2.write("start time: " + str(datetime.datetime.now()) + "\n")
        except InvalidOptionValue as msg:
            print(msg)
            sys.exit(2)
        
        try:
            # crawling
            if self.attack_module.has_scan_started():
                if self.attack_module.have_attacks_started():
                    pass
                else:
                    print(("[*] Resuming scan from previous session, please wait"))
                    self.attack_module.browse()
            else:
                self.attack_module.browse()
            
            print(Fore.YELLOW + ("[*] Wapiti found {0} URLs and forms during the scan").format(self.attack_module.count_resources()) + Fore.RESET)

            # load xss module
            
            logger = ConsoleLogger()

            mod_name = "mod_xss"
            mod = import_module("gym_reflected_xss.attack_module.attack." + mod_name)
            mod_instance = getattr(mod, mod_name)(self.attack_module.crawler, self.attack_module.persister, logger, self.attack_module.attack_options)
            if hasattr(mod_instance, "set_timeout"):
                mod_instance.set_timeout(self.attack_module.crawler.timeout)
            
            self.attack_module.__class__.xss_module = mod_instance
            
            # wap.attacks.append(mod_instance)
            # wap.attacks.sort(key=attrgetter("PRIORITY"))

            # start attack (original code)
            """
            try:
                wap.attack()
            except KeyboardInterrupt:
                print('')
                print(("Attack process interrupted. Scan will be resumed next time "
                        "unless you specify \"--flush-attacks\" or \"--flush-session\"."))
                print('')
                pass
            """

            # only for xss attack
            self.attack_module.xss_module.log_green(("[*] Launching module {0}"), self.attack_module.xss_module.name)
            print(Fore.GREEN + "[*] Attack module configuration complete " + Fore.RESET)
            
            self.attack_module.xss_module.file = self.f
            self.attack_module.xss_module.file2 = self.f2

            

            self.http_resources = self.attack_module.xss_module.persister.get_links(attack_module=self.attack_module.xss_module.name) if self.attack_module.xss_module.do_get else []
            self.forms = self.attack_module.xss_module.persister.get_forms(attack_module=self.attack_module.xss_module.name) if self.attack_module.xss_module.do_post else []

            self.injection_points = chain(self.http_resources, self.forms)
            """ self.current_original_request = next(self.injection_points) """
            # only one url for each episode
            self.request_list = list(self.injection_points)
            # print(self.request_list)
            """self.current_injection_points = self.mutator.mutate(self.current_original_request)
            while True:
                try:
                    self.mutated_request, self.parameter, self.taint, self.flags = next(self.current_injection_points)
                    self.tried_request = False
                    self.num_tried = 0
                    break
                except StopIteration:
                    try:
                        self.current_original_request =  next(self.injection_points)
                        self.current_injection_points = self.mutator.mutate(self.current_original_request)       
                    except StopIteration:
                        raise Exception("Nothing to attack")
            """
        except SystemExit:
            pass

    def pick_injection_url(self):
       
        def Extract(lst):
            return [item[0] for item in lst]
        
        def choiceFromRequestList():
            
            if self.mode != 1 :
                self.request_list_index = self.request_list_index + 1
                if self.request_list_index == len(self.request_list):
                    self.request_list_index = 0
                
            elif self.mode == 1 and self.current_original_request != None:
                # remove all same value from the list
                
                self.request_list = list(filter(lambda a: a != self.current_original_request, self.request_list))
                
                
                if self.current_original_request.post_params != []:
                    self.request_list = list(filter(lambda a: ((a.url.split("?")[0] != self.current_original_request.url.split("?")[0]) or (Extract(a.post_params) != Extract(self.current_original_request.post_params) and Extract(a.get_params) != Extract(self.current_original_request.post_params))) ,self.request_list))

                if self.current_original_request.get_params != []:
                    self.request_list = list(filter(lambda a: ((a.url.split("?")[0] != self.current_original_request.url.split("?")[0]) or (Extract(a.get_params) != Extract(self.current_original_request.get_params) and Extract(a.post_params) != Extract(self.current_original_request.get_params))) ,self.request_list))
                
            currentRequest = self.request_list[self.request_list_index]
            #print(currentRequest)
            return currentRequest


        target_removed = False
        other_param_used = False
         # if attack mode, not try success attack url again 
        if self.find_vul != 1 or self.mode == 1:
            # try other parameters
            if self.current_original_request != None and self.current_injection_points != None:
                print("try other parameters")
                if self.paramType == 0:
                    try: 
                        # next parameter
                        while True:
                            self.mutated_request, self.parameter, self.taint, self.flags = next(self.current_injection_points)
                            try:
                                if not (self.parameter in self.attacked[self.current_original_request.url.split("?")[0]]): 
                                    self.attacked[self.current_original_request.url.split("?")[0]].append(self.parameter)
                                    print(self.attacked)
                                    break   
                            except:
                                self.attacked[self.current_original_request.url.split("?")[0]] = [self.parameter]
                                break 

                        other_param_used = True     
                    except:
                        # try referer header, 0: paramter, 1: referer, 2: url
                        if self.current_original_request.url.split("?")[0] not in self.try_list_referer:
                            self.try_list_referer.append(self.current_original_request.url.split("?")[0])
                            self.paramType = 1 
                            other_param_used = True
                        elif self.current_original_request.url.split("?")[0] not in self.try_list_url:
                            self.try_list_url.append(self.current_original_request.url.split("?")[0])
                            self.paramType = 2 
                            other_param_used = True
                        else: 
                            self.paramType = 0
                            other_param_used = False
                else:
                    if self.paramType == 1:
                        if self.current_original_request.url.split("?")[0] not in self.try_list_url:
                            self.try_list_url.append(self.current_original_request.url.split("?")[0])
                            self.paramType = 2 
                            other_param_used = True
                        else:
                            self.paramType = 0
                            other_param_used = False
                    else:
                        self.paramType = 0
                        other_param_used = False
                        
                
            
            
            refererUsed = False
            # try other url    
            if not other_param_used:

                methods = ""
                if self.attack_module.xss_module.do_get:
                    methods += "G"
                if self.attack_module.xss_module.do_post:
                    methods += "PF"
                self.mutator = Mutator(
                    methods=methods,
                    payloads=self.attack_module.xss_module.random_string,
                    qs_inject=self.attack_module.xss_module.must_attack_query_string,
                    skip=self.attack_module.xss_module.options.get("skipped_parameters")
                )

                
                find_injection_point = False
                while not find_injection_point:

                    if len(self.request_list) == 0:
                        print("done")
                        quit()

                    self.current_original_request = choiceFromRequestList()
                    self.current_injection_points = self.mutator.mutate(self.current_original_request) 

                    # block logout url, out of scope url 
                    #block = True
                    block = False
                    if self.current_original_request != None:
                        for u in self.url_block_list:
                            if u in self.current_original_request.url or self.current_original_request.url in u:
                                block = True
                                #block = False
                                break
                            
                    if not block:
                        # if there is no available parameter, try referer header
                        if self.current_original_request.get_params == [] and self.current_original_request.post_params == [] and self.paramType == 0:
                            # PayloadType.get = enum(3)
                            if self.current_original_request.url.split("?")[0] not in self.try_list_referer:
                                self.flags = set([3])
                                self.taint = None
                                refererUsed = True
                                find_injection_point = True
                                break
                            
                        else:  
                            
                            # find parameter
                            try:
                                while True:
                                    self.mutated_request, self.parameter, self.taint, self.flags = next(self.current_injection_points)
                                    try:
                                        if not (self.parameter in self.attacked[self.current_original_request.url.split("?")[0]]): 
                                            self.attacked[self.current_original_request.url.split("?")[0]].append(self.parameter)
                                            print(self.attacked)
                                            break   
                                    except:
                                        self.attacked[self.current_original_request.url.split("?")[0]] = [self.parameter]
                                        break 
                            except StopIteration:
                                find_injection_point = False
                            else:    
                                find_injection_point = True
                                
                                    
                
                self.tried_request = False
                self.num_tried = 0

                if refererUsed:
                    self.paramType = 1                        
                    
                self.removeInjectionTarget = False
            self.find_vul = 0
            


    def step(self, action):
        
        self.totalStepCounter += 1
        # logger
        self.f.write("----------------step log----------------\n")
        self.f.write("time: " + str(datetime.datetime.now()) + "\n")
        if(len(str(self.current_original_request)) < 500):
            self.f.write("url: "  +str(self.current_original_request)  + "\n")
        self.f.write("action: " + str(action) + "\n")
        """Run one timestep of the environment's dynamics.
        Accepts an action and returns a tuple (observation, reward, done, info).
        Args:
            action (Enum): action value
        Returns:
            tuple:
                - observation (Enum): Agent's observation of the current environment.
                - reward (float) : Amount of reward returned after previous action.
                - done (bool): Whether the episode has ended, in which case further step() calls will return undefined results.
                - info (str): (optional) Contains auxiliary diagnostic information (helpful for debugging, and sometimes learning).
        """
        # make new input for corresponding action, and do next attack with new input
        
        self.action = action

        xss_module = self.attack_module.xss_module
        generated_input = self.input_module.do_action(action, self.max_try)
        
        
        attack_success = False
        # attack phase
        if not self.tried_request:
            self.num_tried += 1
            try:
                self.tried_request = True    
                # We keep a history of taint values we sent because in case of stored value, the taint code
                # may be found in another webpage by the permanentxss module.       
                #xss_module.TRIED_XSS[self.taint] = (self.mutated_request, self.parameter, self.flags)

                # Reminder: valid_xss_content_type is not called before before content is not necessary
                # reflected here, may be found in another webpage so we have to inject tainted values
                # even if the Content-Type seems uninteresting.
                payloads = (generated_input, self.flags)
                
                
                if PayloadType.get in self.flags:
                    method = "G"
                elif PayloadType.file in self.flags:
                    method = "F"
                else:
                    method = "P"
                self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
                attack_success, status = xss_module.attempt_exploit(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType) 
                
                
            except ReadTimeout:
                pass 
        else:
            try:
                self.num_tried += 1
                payloads = (generated_input, self.flags)
                
                if PayloadType.get in self.flags:
                    method = "G"
                elif PayloadType.file in self.flags:
                    method = "F"
                else:
                    method = "P"
                self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
                attack_success, status = xss_module.attempt_exploit(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType)
            except ReadTimeout:
                pass 
        
        if attack_success:
            
            self.numVulCounter += 1
            
            self.removeInjectionTarget = True
            self.find_vul = 2
        
        
        if self.block_obs != -1:
            if self.block_obs == 30 or self.block_obs == 31 or self.block_obs == 33:
                status[self.block_obs] = -1
            else:
                status[self.block_obs] = 0
        
        xss_module.current_state = np.array(status.copy())
        self._observation = np.array(status.copy())
        reward = self._compute_reward(status)
        
        #if attack_success:
            #self.f3.write(str(self.num_tried) + "\n")
        
        self._envStepCounter += 1

        # try 50 times per each injection point
        self.f.write("try: "+ str(self.num_tried) + "\n")
        if self.num_tried == self.max_try:
            attack_success = True

            

        

        if attack_success:
            #print("url: " + str(self.current_original_request))
            # log # of steps
            if self.num_tried < 2:
                self.num_steps_list[0] = self.num_steps_list[0] + 1
            elif self.num_tried < 5:
                self.num_steps_list[1] = self.num_steps_list[1] + 1
            elif self.num_tried < 10:
                self.num_steps_list[2] = self.num_steps_list[2] + 1
            elif self.num_tried < 20:
                self.num_steps_list[3] = self.num_steps_list[3] + 1
            elif self.num_tried < 50:
                self.num_steps_list[4] = self.num_steps_list[4] + 1
            elif self.num_tried < 100:
                self.num_steps_list[5] = self.num_steps_list[5] + 1
            elif self.num_tried < 500:
                self.num_steps_list[6] = self.num_steps_list[6] + 1
            elif self.num_tried < 1000:
                self.num_steps_list[7] = self.num_steps_list[7] + 1
            self.attack_module.done = True
            self.tried_request = False
            self.num_tried = 0
            self.tried_request = False
            self.input_module = InputGenerator()
            self.input_module.initialize_all_state()
            # print(self.num_steps_list)
            
            
            
        done = self._compute_done()
            # self.find_where_injected()
        
        # logger
        self.f.write("state: " + str(self._observation) +"\n")
        # self.action_dict[str(action)] += 1
        self.f.write("----------------------------------------\n")
        
        #print("state: " + str(self._observation) +"\n")
        return self._observation, reward, done, {}

    def reset(self):
        """Reset the state of the environment and returns an initial observation.
        Returns:
            Enum: The initial observation of the space. Initial reward is assumed to be 0.
        """
        self._envStepCounter = 0

        # find possible attack url (have relfected parameter)
        found = False
        while not found:

            self.pick_injection_url()
            self.attack_module.done = False
            self.input_module = InputGenerator()
            
            found = self.find_where_injected()
        
        self.find_vul = 1
        if self.block_obs != -1:
            if self.block_obs == 30 or self.block_obs == 31 or self.block_obs == 33:
                self.initial_status[self.block_obs] = -1
            else:
                self.initial_status[self.block_obs] = 0

        self._observation = self.initial_status
        print(self.initial_status)
        self.input_module.status = self.initial_status
        
        return self._observation

    def render(self):
        pass
    
    def seed(self):
        pass

    def _compute_observation(self):
        return self.attack_module.xss_module.current_state
    
    def _compute_reward(self, status):
        
        reward = 0

        if status[obs.ATTACK_SUCCESS] == 1:
            reward += self.max_try - self._envStepCounter 

        if status[obs.PREVIOUS_ACTION] == status[obs.CURRENT_ACTION]:
            reward -= 1

        if self.input_module.current_input == self.input_module.previous_input:
            reward -= 1
       
        if self._envStepCounter > 0:
            reward -= status[obs.INPUT_CORPUS] 
        
        return reward 

    def _compute_done(self):
        return self.attack_module.done
    
    
    def find_where_injected(self):
        
        found = False
        print("url: "  + str(self.current_original_request.url))
        self.initial_status = np.array([0.0] * self.state_size)
        xss_module = self.attack_module.xss_module
        
        if self.paramType == 0:
            print(self.parameter + " injection")
        elif self.paramType == 1:
            print("referer injection")
        else:
            print("url injection")
        
        if len(self.flags) == 0: 
            self.flags.add(PayloadType.get)

        self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
        if "email" in self.parameter:
            payloads = ("1209@0727", self.flags)
        else:
            payloads = ("12090727'", self.flags)
        if PayloadType.get in self.flags:
            method = "G"
        elif PayloadType.file in self.flags:
            method = "F"
        else:
            method = "P"

        
        status = xss_module.find_injection_point(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType)
        self.initial_status[obs.CONTENT_TYPE] = status[0]
        self.initial_status[obs.INJECTION_POINT_TYPE] = status[1]
        self.initial_status[obs.BEFORE_INJECTION_POINT] = status[2]
        self.initial_status[obs.BEHIND_INJECTION_POINT] = status[6]
        self.initial_status[obs.ESCAPE_STRING] = status[5]
        self.initial_status[obs.DEFAULT_PAYLOAD_TYPE] = status[4]
        self.initial_status[obs.EFFECTIVE_TAG_TYPE] = status[7]
        if status[3] == 1:
            found = True

            self.initial_status[obs.FOURTH_MAGIC_STRING] = 1
            

        else:
            
            self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
            payloads = ('"' + "/" + "'" +  "injectionhere0727", self.flags)
                
            if PayloadType.get in self.flags:
                method = "G"
            elif PayloadType.file in self.flags:
                method = "F"
            else:
                method = "P"
            status = xss_module.find_injection_point(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType)
            
            if status[3] == 1:
                found = True
                
                self.initial_status[obs.CONTENT_TYPE] = status[0]
                self.initial_status[obs.INJECTION_POINT_TYPE] = status[1]
                self.initial_status[obs.BEFORE_INJECTION_POINT] = status[2]
                self.initial_status[obs.BEHIND_INJECTION_POINT] = status[6]
                self.initial_status[obs.ESCAPE_STRING] = status[5]
                self.initial_status[obs.DEFAULT_PAYLOAD_TYPE] = status[4]
                self.initial_status[obs.EFFECTIVE_TAG_TYPE] = status[7]
                
                
                
                
                
        
        if found:
            if PayloadType.get in self.flags:
                method = "G"
            elif PayloadType.file in self.flags:
                method = "F"
            else:
                method = "P"

            payloads = ("'" + "</script>"+ '"' +"alert" + "injectionhere0727" , self.flags)
            status = xss_module.find_injection_point(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType)
            # payload: '</script>alertinjectionhere0727
            self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
            if status[3] == 1:
                found = True
                self.initial_status[obs.FIRST_MAGIC_STRING] = 1
                self.initial_status[obs.SECOND_MAGIC_STRING] = 1
                self.initial_status[obs.THIRD_MAGIC_STRING] = 1

                
                
            else:
                self.f.write("attack time: " + str(datetime.datetime.now()) + "\n")
                payloads = ("/" + "'" + '"' + "alert" + "injectionhere0727", self.flags)
                # /'>">alertinjectionhere0727
                if PayloadType.get in self.flags:
                    method = "G"
                elif PayloadType.file in self.flags:
                    method = "F"
                else:
                    method = "P"
                status = xss_module.find_injection_point(method, payloads, self.current_original_request, self.parameter, self.taint, self.input_module, self.paramType)
                if status[3] == 1:
                    found = True
                    self.initial_status[obs.SECOND_MAGIC_STRING] = 1
                    self.initial_status[obs.THIRD_MAGIC_STRING] = 1
                    
        return found
