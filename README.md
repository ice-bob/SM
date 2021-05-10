# SM
国密 by python

SM3 算法实现，支持输入为 *int* 或者 *str*：
```python
s = SM3.SM3("abc")
hash_value = s.update()

s = SM3.SM3(0x616263)
hash_value = s.update()
```
