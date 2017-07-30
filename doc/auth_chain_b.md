# auth_chain_b

**Note:**  
以下内容来自对breakwa11的第一版Python与C#源码的人工分析与推定结果

## TCP

auth_chain_b 与 auth_chain_a 最大不同在于重新定义了TCP部分非首包的随机填充数据的长度计算函数

以Python代码为例

### auth_chain_a的长度计算函数实现如下  
```python
    def rnd_data_len(self, buf_size, last_hash, random):
        if buf_size > 1440:
            return 0
        random.init_from_bin_len(last_hash, buf_size)
        if buf_size > 1300:
            return random.next() % 31
        if buf_size > 900:
            return random.next() % 127
        if buf_size > 400:
            return random.next() % 521
        return random.next() % 1021
```
其中random为XorShift128Plus快速伪随机数生成器

此函数输入原始数据长度，返回需补全的随机数据长度  
简单的说，此函数使得算法将原始包随机填充不定长的随机数据，使得填充后的包长度随机分布在[原始包~1440)之间


### auth_chain_b的新的长度计算函数实现如下  
```python
    def rnd_data_len(self, buf_size, last_hash, random):
        if buf_size >= 1440:
            return 0
        random.init_from_bin_len(last_hash, buf_size)
        pos = bisect.bisect_left(self.data_size_list, buf_size + self.server_info.overhead)
        final_pos = pos + random.next() % (len(self.data_size_list))
        # 假设random均匀分布，则越长的原始数据长度越容易if false
        if final_pos < len(self.data_size_list):
            return self.data_size_list[final_pos] - buf_size - self.server_info.overhead

        # 上面if false后选择2号补全数组，此处有更精细的长度分段
        pos = bisect.bisect_left(self.data_size_list2, buf_size + self.server_info.overhead)
        final_pos = pos + random.next() % (len(self.data_size_list2))
        if final_pos < len(self.data_size_list2):
            return self.data_size_list2[final_pos] - buf_size - self.server_info.overhead
        # final_pos 总是分布在pos~(data_size_list2.len-1)之间
        if final_pos < pos + len(self.data_size_list2) - 1:
            return 0
        # 有1/len(self.data_size_list2)的概率不满足上一个if  ????
        # 理论上不会运行到此处，因此可以插入运行断言
        # assert False

        if buf_size > 1300:
            return random.next() % 31
        if buf_size > 900:
            return random.next() % 127
        if buf_size > 400:
            return random.next() % 521
        return random.next() % 1021
```

对所有能够进行填充的包，将其的大小填充到data_size_list或data_size_list2数组中预定义的某个可能的长度

其中data_size_list和data_size_list2数组在连接建立时使用如下代码进行初始化
```python
    def init_data_size(self, key):
        if self.data_size_list:
            self.data_size_list = []
            self.data_size_list2 = []
        random = xorshift128plus()
        random.init_from_bin(key)
        # 补全数组长为4~12-1
        list_len = random.next() % 8 + 4
        for i in range(0, list_len):
            self.data_size_list.append((int)(random.next() % 2340 % 2040 % 1440))
        self.data_size_list.sort()
        # 补全数组长为8~24-1
        list_len = random.next() % 16 + 8
        for i in range(0, list_len):
            self.data_size_list2.append((int)(random.next() % 2340 % 2040 % 1440))
        self.data_size_list2.sort()
```
data_size_list会被初始化为4\~11个元素  
data_size_list2会被初始化为8\~23个元素  

初始化之后rnd_data_len会先在`[data_size_list中最小可能pos~data_size_list中最小可能pos+len(data_size_list))`中随机寻找一个可能的填充长度值  
若寻找失败`(随机选取结果落在data_size_list之外)`则在`[data_size_list2中最小可能pos~data_size_list2中最小可能pos+len(data_size_list2))`中随机寻找一个可能的填充长度值  
若仍然寻找失败`(随机选取结果落在data_size_list2之外)`则不填充

因data_size_list与data_size_list2会被用户密码生成的key初始化的伪随机数生成器初始化  
故使用相同的用户密码会生成一致的data_size_list与data_size_list2  
此特性即为传说中的`更换密码即更换特征(包长度统计特征)`  
*猜测：在连接建立时初始化data_size_list与data_size_list2和在进程启动时初始化data_size_list与data_size_list2的结果没有区别*  
*因此可以共用data_size_list与data_size_list2*

但根据代码所显示的，填充后的包长度有一定概率为data_size_list或data_size_list2中的长度，而剩余概率下不填充则为原始长度  
因此此算法的填充结果为某些由用户密码决定的定值或为原始长度  
但当用户密码生成的data_size_list序列长度中的填充目标长度均过短时，有更大概率会导致总是不进行填充


## UDP

UDP部分不变


# 改进的可能

### 改进方向
1. 使得所有包均填充至data_size_list与data_size_list2中的某个大小
1. 一定无法填充为data_size_list与data_size_list2中的某个大小的包继续使用随机长度填充或0长度填充
1. 修改data_size_list与data_size_list2的生成算法使其的范围能够容纳所有可能长度的包 **(<==较难实现)**
1. 优化data_size_list的初始化过程，在进程启动时初始化一个全局版本的data_size_list，使得所有连接共用data_size_list，降低连接创建时的计算复杂度，增强包特征

### 实现方法
```python

    # in the init_data_size() function
    self.data_size_list0 = (self.data_size_list + self.data_size_list2)
    self.data_size_list0.sort()

    def rnd_data_len(self, buf_size, last_hash, random):
        # final_pos 总是分布在pos~(data_size_list0.len-1)之间
        # 除非data_size_list0中的任何值均过小使其全部都无法容纳buf
        if buf_size >= self.data_size_list0[-1]:
            if buf_size >= 1440:
                return 0
            if buf_size > 1300:
                return random.next() % 31
            if buf_size > 900:
                return random.next() % 127
            if buf_size > 400:
                return random.next() % 521
            return random.next() % 1021

        random.init_from_bin_len(last_hash, buf_size)
        pos = bisect.bisect_left(self.data_size_list0, buf_size + self.server_info.overhead)
        final_pos = pos + random.next() % (len(self.data_size_list0) - pos)
        return self.data_size_list0[final_pos] - buf_size - self.server_info.overhead

```


*什么时候我弄个auth_chain_c出来就按照上面这个方向进行改进好了(笑*

