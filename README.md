# Link
Link is a general RL framework to find reflected XSS vulnerabilities in a black-box and fully automatic manner. It implemented on top of [Wapiti](https://github.com/wapiti-scanner/wapiti) a popular open source web scanner. And reinforcement learning components are implemeted based on [OpenAI gym](https://gym.openai.com/) and [Stable baselines](https://github.com/hill-a/
stable-baselines)
The details of Link is in our [paper](https://dl.acm.org/doi/10.1145/3485447.3512234), "Link: Black-Box Detection of Cross-Site Scripting Vulnerabilities
Using Reinforcement Learning" which appeared in The Web Conference 2022. 

## Requirements

- Recommend to use Anaconda3 
- Tensorflow==1.14
- gym
- stable-baselines
  

## Instruction 
### Training Session

    $ python3 train.py -u <training application url> -t <timesteps>
    $ python3 train.py -u 'http://localhost:8080' -t 200000



### XSS detection phase using trained agent

    $ python3 attack_A2C.py -u <target url> -n <model name>
    $ python3 attack_A2C.py -u 'http://localhost:8080' -n sample_agent.pkl


### Training visulization (Tensorboard)

    $ tensorboard --logdir [log directory name]
    $ tensorboard --logdir ./tensorboard_log/


## Test Suite Installation
### [Google Firing Range](https://github.com/google/firing-range)
1. `sudo apt-get install git ant`
2. Download Google AppEngine SDK file in test suite dependency folder and unzip it
3. `git clone https://github.com/google/firing-range.git`
4. `cd firing-range`
5. Modify `build.xml`, `appengine.sdk` should be your own path of extracted folder
6. Add below code on line 70 in `build.xml`
   
   `<get src="https://repo1.maven.org/maven2/servletapi/servlet-api/2.4/servlet-api-2.4.jar" dest="${war.dir}/WEB-INF/lib"/>`
    
7. `ant runserver`
8. Test Suite will run on `localhost:8080`
9. You should kill process before restart 
~~~
    $ sudo netstat -lpn |grep :8080
    $ kill process_id
~~~
### [OWASP Benchmark](https://owasp.org/www-project-benchmark/)

    $ git clone https://github.com/OWASP/benchmark 
    $ cd benchmark
    $ mvn compile   (This compiles it)
    $ sudo runBenchmark.sh/.bat - This compiles and runs it.

- Access on `https://localhost:8443/benchmark/`


### [WAVSEP](https://code.google.com/archive/p/wavsep/)

    $ docker pull owaspvwad/wavsep
    $ docker run -p 127.0.0.1:8090:8080 owaspvwad/wavsep

- Access on `http://localhost:8090/wavsep/active/index-xss.jsp`



## Authors 
* Soyoung Lee
* [Seongil Wi](https://seongil-wi.github.io/)
* [Sooel Son](https://sites.google.com/site/ssonkaist/home)

## Citing Link

To cite our paper:
```
@inproceedings{lee:www:2022,
    author = {Lee, Soyoung and Wi, Seongil and Son, Sooel},
    title = {Link: Black-Box Detection of Cross-Site Scripting Vulnerabilities Using Reinforcement Learning},
    year = {2022},
    booktitle = {Proceedings of the ACM Web Conference 2022},
}

```