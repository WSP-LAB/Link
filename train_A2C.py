import sys
import getopt
import time
import gym
import gym_reflected_xss
import uuid
from stable_baselines.common.vec_env import DummyVecEnv
from stable_baselines3.a2c.policies import MlpPolicy, CnnPolicy


from stable_baselines import A2C
from stable_baselines.common import make_vec_env
import torch as th
# remove tensorflow warning messages
import warnings
warnings.simplefilter(action='ignore', category=FutureWarning)
import tensorflow as tf
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.ERROR)

from stable_baselines.common.policies import FeedForwardPolicy, LstmPolicy
# Custom MLP policy of three layers of size 128 each
class CustomPolicy(FeedForwardPolicy):
    def __init__(self,*args, **kwargs):
        super(CustomPolicy, self).__init__(*args, **kwargs, 
                                           net_arch=[dict(pi=[128, 128, 128],
                                                          vf=[128, 128, 128])],
                                           feature_extraction="mlp")
class CustomLSTMPolicy(LstmPolicy):
    def __init__(self, sess, ob_space, ac_space, n_env, n_steps, n_batch, n_lstm=128, reuse=False, **_kwargs):
        super().__init__(sess, ob_space, ac_space, n_env, n_steps, n_batch, n_lstm, reuse,
                         net_arch=[128, 'lstm', dict(pi=[128, 128, 128],
                                                    vf=[128, 128, 128])],
                         layer_norm=True, feature_extraction="mlp", **_kwargs)

def main(argv):
    start_url = ""
    test_suite_name = ""
    timesteps = 4000000

    try:
        opts, etc_args= getopt.getopt(argv[1:], "o:t:")
    except getopt.GetoptError:
        print("Use option -o")
        sys.exit(2)
    
    for opt,arg in opts:
        if opt in ("-u"):
            option = arg
        if opt in ("-t"):
            timesteps = int(arg)

    
    start_url = option

    
    env = gym.make("reflected-xss-v0", start_url=start_url, mode=0, log_file_name="train_log.txt")

    # create learning agent 
    print("[*] Creating A2C model ...")  
    policy_kwargs = dict(activation_fn=th.nn.ReLU,net_arch=[dict(pi=[128,128,128], vf=[128,128,128])])

    learning_rate = 0.0005
    gamma = 0.95
    model = A2C(CustomPolicy, env, verbose=1,tensorboard_log="./tensorboard_log/", learning_rate=learning_rate, gamma=gamma)   
    print("[*] Start Agent learning ...")


    log_title = time.strftime('%Y.%m.%d', time.localtime(time.time())) + "-" + test_suite_name +  "-" + str(timesteps) + "-A2C-learning-" + str(learning_rate) + "-gamma-" + str(gamma) + "O"

    model.learn(total_timesteps=timesteps , tb_log_name=log_title)
    
    model_name = "models/" + log_title + "-" + str(uuid.uuid4()) + "-model.pkl"

    # save trained model
    model.save(model_name)

    # env.show_graph()

    del model

if __name__ == '__main__':
    main(sys.argv)

