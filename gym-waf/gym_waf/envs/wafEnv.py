# -*- coding:utf-8 –*-
import numpy as np
import random
from gym import spaces
import gym
from gym_waf.envs.features import Features
from gym_waf.envs.waf import Waf_Check
from gym_waf.envs.xss_manipulator import Xss_Manipulator
from sklearn.model_selection import train_test_split

samples_file = "xss-samples-all.txt"
samples = []
with open(samples_file) as f:
    for line in f:
        line = line.strip('\n')
        print("Add xss sample:" + line)
        samples.append(line)

# 划分训练和测试集合
samples_train, samples_test = train_test_split(samples, test_size=0.4)

ACTION_LOOKUP = {i: act for i, act in enumerate(Xss_Manipulator.ACTION_TABLE.keys())}

class WafEnv_v0(gym.Env):
    metadata = {
        'render.modes': ['human', 'rgb_array'],
    }

    def __init__(self):
        self.action_space = spaces.Discrete(len(ACTION_LOOKUP))

        self.current_sample = ""
        self.features_extra = Features()
        self.waf_checker = Waf_Check()
        self.xss_manipulatorer = Xss_Manipulator()

        # 假设 features_extra.extract 返回一个 257 维特征
        self.observation_space = spaces.Box(low=-np.inf, high=np.inf, shape=(257,), dtype=np.float32)

        self.reset()

    # 添加 seed 方法
    def seed(self, seed=None):
        random.seed(seed)
        np.random.seed(seed)

    def reset(self):
        self.current_sample = random.choice(samples_train)
        print("reset current_sample=" + self.current_sample)

        # 提取样本特征
        observation = self.features_extra.extract(self.current_sample)
        
        if observation is None:
            raise ValueError("Extracted observation is None")
        
        # 确保 observation 是 257 维的，并且是 float32 类型
        observation = np.asarray(observation, dtype=np.float32)
        if observation.shape[0] != 257:
            print(f"Warning: Unexpected observation shape: {observation.shape}")

        info = {}  # 如果不需要返回其他信息，返回空字典
        return observation, info

    def step(self, action):
        r = 0
        is_gameover = False

        _action = ACTION_LOOKUP[action]
        self.current_sample = self.xss_manipulatorer.modify(self.current_sample, _action)

        if not self.waf_checker.check_xss(self.current_sample):
            r = 10
            is_gameover = True
            print("Good!!!!!!!avoid waf:%s" % self.current_sample)

        # 获取当前样本的特征并确保形状和类型正确
        observation = self.features_extra.extract(self.current_sample)
        observation = np.asarray(observation, dtype=np.float32)
        print(f"Extracted feature shape (step): {observation.shape}")

        if observation.shape[0] != 257:
            print(f"Warning: Unexpected observation shape: {observation.shape}")
        
        return observation, r, is_gameover, {}

    def render(self, mode='human', close=False):
        return

# 训练 DQN 模型
def train_dqn_model(layers, rounds=10000):
    ENV_NAME = 'WafEnv-v0'
    env = gym.make(ENV_NAME)

    # 使用 numpy 设置随机种子
    np.random.seed(1)
    env.seed(1)  # 调用自定义的 seed 方法

    nb_actions = env.action_space.n
    window_length = 1

    print("nb_actions:")
    print(nb_actions)
    print("env.observation_space.shape:")
    print(env.observation_space.shape)

    model = generate_dense_model((window_length,) + env.observation_space.shape, layers, nb_actions)

    policy = EpsGreedyQPolicy()
    memory = SequentialMemory(limit=256, ignore_episode_boundaries=False, window_length=window_length)

    agent = DQNAgent(model=model, nb_actions=nb_actions, memory=memory, nb_steps_warmup=16,
                     enable_double_dqn=True, enable_dueling_network=True, dueling_type='avg',
                     target_model_update=1e-2, policy=policy, batch_size=16)

    agent.compile(RMSprop(learning_rate=1e-3), metrics=['mae'])

    agent.fit(env, nb_steps=rounds, nb_max_episode_steps=1000, visualize=False, verbose=2)

    test_samples = samples_test
    features_extra = Features()
    waf_checker = Waf_Check()
    xss_manipulatorer = Xss_Manipulator()

    success = 0
    sum = 0
    shp = (1,) + tuple(model.input_shape[1:])

    for sample in samples_test:
        sum += 1
        for _ in range(1000):
            if not waf_checker.check_xss(sample):
                success += 1
                print(sample)
                break

            f = features_extra.extract(sample).reshape(shp)
            act_values = model.predict(f)
            action = np.argmax(act_values[0])
            sample = xss_manipulatorer.modify(sample, ACTION_LOOKUP[action])

    print("Sum:{} Success:{}".format(sum, success))

    return agent, model

if __name__ == '__main__':
    agent1, model1 = train_dqn_model([5, 2], rounds=1000)
    model1.save('waf-v0.h5', overwrite=True)
