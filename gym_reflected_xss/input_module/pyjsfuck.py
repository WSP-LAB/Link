#!/usr/bin/env python


import execjs


class JSFuck():

    def __init__(self):
        f = open('gym_reflected_xss/input_module/jsfuck.js', 'r')
        jsf_code = f.read()
        js = execjs.get()
        #print "Using Engine %s" % js.name
        self.jsf_int = js.compile(jsf_code)
        pass

    def encode(self, code):
        return self.jsf_int.call('JSFuck',code,'1')


if __name__ == '__main__':
    code = 'alert(1);'
    jsf = JSFuck()
    string = jsf.encode(code)
    print(string)
