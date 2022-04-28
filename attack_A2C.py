import sys
import getopt
import gym
import gym_reflected_xss

# from baselines import deepq
# from baselines.logger import Logger, TensorBoardOutputFormat, HumanOutputFormat
from stable_baselines.common.vec_env import DummyVecEnv
from stable_baselines.deepq.policies import MlpPolicy
from stable_baselines import DQN, A2C

# remove tensorflow warning messages
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import tensorflow as tf
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)

def callback(lcl, glb):
    # stop training if reward exceeds 199 
    is_solved = lcl['t'] > 100 and sum(lcl['epsiode_rewards'][-101:-1] / 100 >= 100)
    return is_solved 

def main(argv):

    start_url = ""
    model_name = ""
    option = 0
    
    try:
        opts, etc_args= getopt.getopt(argv[1:], "u:n")
    except getopt.GetoptError:
        print("Use option -o")
        sys.exit(2)
    
    for opt,arg in opts:
        if opt in ("-u"):
            option = arg
        if opt in ("-n"):
            model_name = arg


            
    
    start_url = option
    
    # create the environment 
    env = gym.make("reflected-xss-v0", start_url=start_url, mode=1, log_file_name="model_log.txt", block_obs=-1)

    # create learning agent 
    print("[*] Loading A2Cmodel ...")

    model = A2C.load("models/" + model_name)
    print("[*] Start Agent working ...")
    obs = env.reset() 
    numberOfTarget = 0
    

    while True:

        action , _states = model.predict(obs)

        obs, rewards, done, info = env.step(action)
        env.render() 

        if done:
            numberOfTarget += 1
            print("# of status: " + str(numberOfTarget))
            env.reset()
        
   

if __name__ == '__main__':
    main(sys.argv)