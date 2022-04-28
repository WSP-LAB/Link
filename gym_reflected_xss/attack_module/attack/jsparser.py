from pyjsparser import parse

result = parse('var _p = {"web": "http:\/\/localhost\/cms\/chamilo\/","web_url": "http:\/\/localhost\/cms\/chamilo\/web\/","web_relative": "\/","web_course": "http:\/\/localhost\/cms\/chamilo\/courses\/","web_main": "http:\/\/localhost\/cms\/chamilo\/main\/","web_css": "http:\/\/localhost\/cms\/chamilo\/web\/css\/","web_css_theme": "http:\/\/localhost\/cms\/chamilo\/web\/css\/themes\/chamilo\/","web_ajax": "http:\/\/localhost\/cms\/chamilo\/main\/inc\/ajax\/","web_img": "http:\/\/localhost\/cms\/chamilo\/main\/img\/","web_plugin": "http:\/\/localhost\/cms\/chamilo\/plugin\/","web_lib": "http:\/\/localhost\/cms\/chamilo\/main\/inc\/lib\/","web_upload": "http:\/\/localhost\/cms\/chamilo\/app\/upload\/","web_self": "\/cms\/chamilo\/main\/calendar\/agenda_list.php\/alert(0727);\/","self_basename": "alert(0727);","web_query_vars": "","web_self_query_vars": "\/cms\/chamilo\/main\/calendar\/agenda_list.php\/alert(0727);\/","web_cid_query": "","web_rel_code": "\/main\/"}')


# {'type': 'Program', 'body': [{'type': 'ExpressionStatement', 'expression': {'type': 'CallExpression', 'callee': {'type': 'Identifier', 'name': 'alert'}, 'arguments': [{'type': 'Literal', 'value': 1.0, 'raw': '1'}]}}]}

def rec_dict_search(dic):
    found = False
    
    if type(dic) == dict:
        try:
            if dic['type'] == 'CallExpression':
                if dic['callee']['name'] in ["alert","confirm","prompt"]:
                    if dic['arguments']:
                        for elem in dic['arguments']:
                            if elem['raw'] == '0727':
                                found = True
                                return True
            if not found:
                keys=dic.keys()
                for key in keys:
                    if rec_dict_search(dic[key]):
                        found = True
                    if found: break
        except: 
            keys=dic.keys()
            for key in keys:
                if rec_dict_search(dic[key]):
                    found = True
                if found: break
    
    elif type(dic) == str:
        return False

    elif type(dic) == list:
        for elem in dic:
            keys=elem.keys()
            for key in keys:
                if rec_dict_search(elem[key]):
                    found = True
                if found: break
            if found: break
    
    return found

try:
    result2 = parse('var a = "!@#4"; /**/ prompt(0727)')
    if rec_dict_search(result2):
        print("detected")
except:
    print("Error")
